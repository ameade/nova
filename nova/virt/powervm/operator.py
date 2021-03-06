# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 IBM
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import decimal
import re
import time

from nova import exception as nova_exception
from nova import utils

from nova.compute import power_state
from nova.openstack.common import cfg
from nova.openstack.common import excutils
from nova.openstack.common import log as logging

from nova.virt.powervm import blockdev
from nova.virt.powervm import command
from nova.virt.powervm import common
from nova.virt.powervm import constants
from nova.virt.powervm import exception
from nova.virt.powervm import lpar as LPAR


LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def get_powervm_operator():
    if CONF.powervm_mgr_type == 'ivm':
        return IVMOperator(common.Connection(CONF.powervm_mgr,
                                             CONF.powervm_mgr_user,
                                             CONF.powervm_mgr_passwd))


def get_powervm_disk_adapter():
    return blockdev.PowerVMLocalVolumeAdapter(
            common.Connection(CONF.powervm_mgr,
                              CONF.powervm_mgr_user,
                              CONF.powervm_mgr_passwd))


class PowerVMOperator(object):
    """PowerVM main operator.

    The PowerVMOperator is intented to wrapper all operations
    from the driver and handle either IVM or HMC managed systems.
    """

    def __init__(self):
        self._operator = get_powervm_operator()
        self._disk_adapter = get_powervm_disk_adapter()
        self._host_stats = {}
        self._update_host_stats()

    def get_info(self, instance_name):
        """Get the current status of an LPAR instance.

        Returns a dict containing:

        :state:           the running state, one of the power_state codes
        :max_mem:         (int) the maximum memory in KBytes allowed
        :mem:             (int) the memory in KBytes used by the domain
        :num_cpu:         (int) the number of virtual CPUs for the domain
        :cpu_time:        (int) the CPU time used in nanoseconds

        :raises: PowerVMLPARInstanceNotFound
        """
        lpar_instance = self._get_instance(instance_name)

        state = constants.POWERVM_POWER_STATE.get(
                lpar_instance['state'], power_state.NOSTATE)
        return {'state': state,
                'max_mem': lpar_instance['max_mem'],
                'mem': lpar_instance['desired_mem'],
                'num_cpu': lpar_instance['max_procs'],
                'cpu_time': lpar_instance['uptime']}

    def instance_exists(self, instance_name):
        lpar_instance = self._operator.get_lpar(instance_name)
        return True if lpar_instance else False

    def _get_instance(self, instance_name):
        """Check whether or not the LPAR instance exists and return it."""
        lpar_instance = self._operator.get_lpar(instance_name)

        if lpar_instance is None:
            LOG.error(_("LPAR instance '%s' not found") % instance_name)
            raise exception.PowerVMLPARInstanceNotFound(
                                                instance_name=instance_name)
        return lpar_instance

    def list_instances(self):
        """
        Return the names of all the instances known to the virtualization
        layer, as a list.
        """
        lpar_instances = self._operator.list_lpar_instances()
        return lpar_instances

    def get_available_resource(self):
        """Retrieve resource info.

        :returns: dictionary containing resource info
        """
        data = self.get_host_stats()
        # Memory data is in MB already.
        memory_mb_used = data['host_memory_total'] - data['host_memory_free']

        # Convert to GB
        local_gb = data['disk_total'] / 1024
        local_gb_used = data['disk_used'] / 1024

        dic = {'vcpus': data['vcpus'],
               'memory_mb': data['host_memory_total'],
               'local_gb': local_gb,
               'vcpus_used': data['vcpus_used'],
               'memory_mb_used': memory_mb_used,
               'local_gb_used': local_gb_used,
               'hypervisor_type': data['hypervisor_type'],
               'hypervisor_version': data['hypervisor_version'],
               'hypervisor_hostname': self._operator.get_hostname(),
               'cpu_info': ','.join(data['cpu_info']),
               'disk_available_least': data['disk_total']}
        return dic

    def get_host_stats(self, refresh=False):
        """Return currently known host stats"""
        if refresh:
            self._update_host_stats()
        return self._host_stats

    def _update_host_stats(self):
        memory_info = self._operator.get_memory_info()
        cpu_info = self._operator.get_cpu_info()

        # Note: disk avail information is not accurate. The value
        # is a sum of all Volume Groups and the result cannot
        # represent the real possibility. Example: consider two
        # VGs both 10G, the avail disk will be 20G however,
        # a 15G image does not fit in any VG. This can be improved
        # later on.
        disk_info = self._operator.get_disk_info()

        data = {}
        data['vcpus'] = cpu_info['total_procs']
        data['vcpus_used'] = cpu_info['total_procs'] - cpu_info['avail_procs']
        data['cpu_info'] = constants.POWERVM_CPU_INFO
        data['disk_total'] = disk_info['disk_total']
        data['disk_used'] = disk_info['disk_used']
        data['disk_available'] = disk_info['disk_avail']
        data['host_memory_total'] = memory_info['total_mem']
        data['host_memory_free'] = memory_info['avail_mem']
        data['hypervisor_type'] = constants.POWERVM_HYPERVISOR_TYPE
        data['hypervisor_version'] = constants.POWERVM_HYPERVISOR_VERSION
        data['hypervisor_hostname'] = self._operator.get_hostname()
        data['extres'] = ''

        self._host_stats = data

    def spawn(self, context, instance, image_id):
        def _create_lpar_instance(instance):
            host_stats = self.get_host_stats(refresh=True)
            inst_name = instance['name']

            # CPU/Memory min and max can be configurable. Lets assume
            # some default values for now.

            # Memory
            mem = instance['memory_mb']
            if mem > host_stats['host_memory_free']:
                LOG.error(_('Not enough free memory in the host'))
                raise exception.PowerVMInsufficientFreeMemory(
                                               instance_name=instance['name'])
            mem_min = min(mem, constants.POWERVM_MIN_MEM)
            mem_max = mem + constants.POWERVM_MAX_MEM

            # CPU
            cpus = instance['vcpus']
            avail_cpus = host_stats['vcpus'] - host_stats['vcpus_used']
            if cpus > avail_cpus:
                LOG.error(_('Insufficient available CPU on PowerVM'))
                raise exception.PowerVMInsufficientCPU(
                                               instance_name=instance['name'])
            cpus_min = min(cpus, constants.POWERVM_MIN_CPUS)
            cpus_max = cpus + constants.POWERVM_MAX_CPUS
            cpus_units_min = decimal.Decimal(cpus_min) / decimal.Decimal(10)
            cpus_units = decimal.Decimal(cpus) / decimal.Decimal(10)

            try:
                # Network
                eth_id = self._operator.get_virtual_eth_adapter_id()

                # LPAR configuration data
                lpar_inst = LPAR.LPAR(
                                name=inst_name, lpar_env='aixlinux',
                                min_mem=mem_min, desired_mem=mem,
                                max_mem=mem_max, proc_mode='shared',
                                sharing_mode='uncap', min_procs=cpus_min,
                                desired_procs=cpus, max_procs=cpus_max,
                                min_proc_units=cpus_units_min,
                                desired_proc_units=cpus_units,
                                max_proc_units=cpus_max,
                                virtual_eth_adapters='4/0/%s//0/0' % eth_id)

                LOG.debug(_("Creating LPAR instance '%s'") % instance['name'])
                self._operator.create_lpar(lpar_inst)
            except nova_exception.ProcessExecutionError:
                LOG.exception(_("LPAR instance '%s' creation failed") %
                            instance['name'])
                raise exception.PowerVMLPARCreationFailed()

        def _create_image(context, instance, image_id):
            """Fetch image from glance and copy it to the remote system."""
            try:
                root_volume = self._disk_adapter.create_volume_from_image(
                        context, instance, image_id)

                self._disk_adapter.attach_volume_to_host(root_volume)

                lpar_id = self._operator.get_lpar(instance['name'])['lpar_id']
                vhost = self._operator.get_vhost_by_instance_id(lpar_id)
                self._operator.attach_disk_to_vhost(
                        root_volume['device_name'], vhost)
            except Exception, e:
                LOG.exception(_("PowerVM image creation failed: %s") % str(e))
                raise exception.PowerVMImageCreationFailed()

        spawn_start = time.time()

        try:
            _create_lpar_instance(instance)
            _create_image(context, instance, image_id)
            LOG.debug(_("Activating the LPAR instance '%s'")
                      % instance['name'])
            self._operator.start_lpar(instance['name'])

            # Wait for boot
            timeout_count = range(10)
            while timeout_count:
                state = self.get_info(instance['name'])['state']
                if state == power_state.RUNNING:
                    LOG.info(_("Instance spawned successfully."),
                             instance=instance)
                    break
                timeout_count.pop()
                if len(timeout_count) == 0:
                    LOG.error(_("Instance '%s' failed to boot") %
                              instance['name'])
                    self._cleanup(instance['name'])
                    break
                time.sleep(1)

        except exception.PowerVMImageCreationFailed:
            with excutils.save_and_reraise_exception():
                # log errors in cleanup
                try:
                    self._cleanup(instance['name'])
                except Exception:
                    LOG.exception(_('Error while attempting to '
                                    'clean up failed instance launch.'))

        spawn_time = time.time() - spawn_start
        LOG.info(_("Instance spawned in %s seconds") % spawn_time,
                 instance=instance)

    def destroy(self, instance_name):
        """Destroy (shutdown and delete) the specified instance.

        :param instance_name: Instance name.
        """
        try:
            self._cleanup(instance_name)
        except exception.PowerVMLPARInstanceNotFound:
            LOG.warn(_("During destroy, LPAR instance '%s' was not found on "
                       "PowerVM system.") % instance_name)

    def capture_image(self, context, instance, image_id, image_meta):
        """Capture the root disk for a snapshot

        :param context: nova context for this operation
        :param instance: instance information to capture the image from
        :param image_id: uuid of pre-created snapshot image
        :param image_meta: metadata to upload with captured image
        """
        lpar = self._operator.get_lpar(instance['name'])
        previous_state = lpar['state']

        # stop the instance if it is running
        if previous_state == 'Running':
            LOG.debug(_("Stopping instance %s for snapshot.") %
                      instance['name'])
            # wait up to 2 minutes for shutdown
            self.power_off(instance['name'], timeout=120)

        # get disk_name
        vhost = self._operator.get_vhost_by_instance_id(lpar['lpar_id'])
        disk_name = self._operator.get_disk_name_by_vhost(vhost)

        # do capture and upload
        self._disk_adapter.create_image_from_volume(
                disk_name, context, image_id, image_meta)

        # restart instance if it was running before
        if previous_state == 'Running':
            self.power_on(instance['name'])

    def _cleanup(self, instance_name):
        lpar_id = self._get_instance(instance_name)['lpar_id']
        try:
            vhost = self._operator.get_vhost_by_instance_id(lpar_id)
            disk_name = self._operator.get_disk_name_by_vhost(vhost)

            LOG.debug(_("Shutting down the instance '%s'") % instance_name)
            self._operator.stop_lpar(instance_name)

            if disk_name:
                # TODO(mrodden): we should also detach from the instance
                # before we start deleting things...
                self._disk_adapter.detach_volume_from_host(disk_name)
                self._disk_adapter.delete_volume(disk_name)

            LOG.debug(_("Deleting the LPAR instance '%s'") % instance_name)
            self._operator.remove_lpar(instance_name)
        except Exception:
            LOG.exception(_("PowerVM instance cleanup failed"))
            raise exception.PowerVMLPARInstanceCleanupFailed(
                                                  instance_name=instance_name)

    def power_off(self, instance_name, timeout=30):
        self._operator.stop_lpar(instance_name, timeout)

    def power_on(self, instance_name):
        self._operator.start_lpar(instance_name)


class BaseOperator(object):
    """Base operator for IVM and HMC managed systems."""

    def __init__(self, connection):
        """Constructor.

        :param connection: common.Connection object with the
                           information to connect to the remote
                           ssh.
        """
        self._connection = None
        self.connection_data = connection

    def _set_connection(self):
        if self._connection is None:
            self._connection = common.ssh_connect(self.connection_data)

    def get_lpar(self, instance_name, resource_type='lpar'):
        """Return a LPAR object by its instance name.

        :param instance_name: LPAR instance name
        :param resource_type: the type of resources to list
        :returns: LPAR object
        """
        cmd = self.command.lssyscfg('-r %s --filter "lpar_names=%s"'
                                    % (resource_type, instance_name))
        output = self.run_command(cmd)
        if not output:
            return None
        lpar = LPAR.load_from_conf_data(output[0])
        return lpar

    def list_lpar_instances(self):
        """List all existent LPAR instances names.

        :returns: list -- list with instances names.
        """
        lpar_names = self.run_command(self.command.lssyscfg('-r lpar -F name'))
        if not lpar_names:
            return []
        return lpar_names

    def create_lpar(self, lpar):
        """Receives a LPAR data object and creates a LPAR instance.

        :param lpar: LPAR object
        """
        conf_data = lpar.to_string()
        self.run_command(self.command.mksyscfg('-r lpar -i "%s"' % conf_data))

    def start_lpar(self, instance_name):
        """Start a LPAR instance.

        :param instance_name: LPAR instance name
        """
        self.run_command(self.command.chsysstate('-r lpar -o on -n %s'
                                                 % instance_name))

    def stop_lpar(self, instance_name, timeout=30):
        """Stop a running LPAR.

        :param instance_name: LPAR instance name
        :param timeout: value in seconds for specifying
                        how long to wait for the LPAR to stop
        """
        cmd = self.command.chsysstate('-r lpar -o shutdown --immed -n %s' %
                                      instance_name)
        self.run_command(cmd)

        # poll instance until stopped or raise exception
        lpar_obj = self.get_lpar(instance_name)
        wait_inc = 1  # seconds to wait between status polling
        start_time = time.time()
        while lpar_obj['state'] != 'Not Activated':
            curr_time = time.time()
            # wait up to (timeout) seconds for shutdown
            if (curr_time - start_time) > timeout:
                raise exception.PowerVMLPAROperationTimeout(
                        operation='stop_lpar',
                        instance_name=instance_name)

            time.sleep(wait_inc)
            lpar_obj = self.get_lpar(instance_name)

    def remove_lpar(self, instance_name):
        """Removes a LPAR.

        :param instance_name: LPAR instance name
        """
        self.run_command(self.command.rmsyscfg('-r lpar -n %s'
                                               % instance_name))

    def get_vhost_by_instance_id(self, instance_id):
        """Return the vhost name by the instance id.

        :param instance_id: LPAR instance id
        :returns: string -- vhost name or None in case none is found
        """
        instance_hex_id = '%#010x' % int(instance_id)
        cmd = self.command.lsmap('-all -field clientid svsa -fmt :')
        output = self.run_command(cmd)
        vhosts = dict(item.split(':') for item in list(output))

        if instance_hex_id in vhosts:
            return vhosts[instance_hex_id]

        return None

    def get_virtual_eth_adapter_id(self):
        """Virtual ethernet adapter id.

        Searches for the shared ethernet adapter and returns
        its id.

        :returns: id of the virtual ethernet adapter.
        """
        cmd = self.command.lsmap('-all -net -field sea -fmt :')
        output = self.run_command(cmd)
        sea = output[0]
        cmd = self.command.lsdev('-dev %s -attr pvid' % sea)
        output = self.run_command(cmd)
        # Returned output looks like this: ['value', '', '1']
        if output:
            return output[2]

        return None

    def get_hostname(self):
        """Returns the managed system hostname.

        :returns: string -- hostname
        """
        output = self.run_command(self.command.hostname())
        return output[0]

    def get_disk_name_by_vhost(self, vhost):
        """Returns the disk name attached to a vhost.

        :param vhost: a vhost name
        :returns: string -- disk name
        """
        cmd = self.command.lsmap('-vadapter %s -field backing -fmt :' % vhost)
        output = self.run_command(cmd)
        if output:
            return output[0]

        return None

    def attach_disk_to_vhost(self, disk, vhost):
        """Attach disk name to a specific vhost.

        :param disk: the disk name
        :param vhost: the vhost name
        """
        cmd = self.command.mkvdev('-vdev %s -vadapter %s') % (disk, vhost)
        self.run_command(cmd)

    def get_memory_info(self):
        """Get memory info.

        :returns: tuple - memory info (total_mem, avail_mem)
        """
        cmd = self.command.lshwres(
            '-r mem --level sys -F configurable_sys_mem,curr_avail_sys_mem')
        output = self.run_command(cmd)
        total_mem, avail_mem = output[0].split(',')
        return {'total_mem': int(total_mem),
                'avail_mem': int(avail_mem)}

    def get_cpu_info(self):
        """Get CPU info.

        :returns: tuple - cpu info (total_procs, avail_procs)
        """
        cmd = self.command.lshwres(
            '-r proc --level sys -F '
            'configurable_sys_proc_units,curr_avail_sys_proc_units')
        output = self.run_command(cmd)
        total_procs, avail_procs = output[0].split(',')
        return {'total_procs': float(total_procs),
                'avail_procs': float(avail_procs)}

    def get_disk_info(self):
        """Get the disk usage information.

        :returns: tuple - disk info (disk_total, disk_used, disk_avail)
        """
        vgs = self.run_command(self.command.lsvg())
        (disk_total, disk_used, disk_avail) = [0, 0, 0]
        for vg in vgs:
            cmd = self.command.lsvg('%s -field totalpps usedpps freepps -fmt :'
                                    % vg)
            output = self.run_command(cmd)
            # Output example:
            # 1271 (10168 megabytes):0 (0 megabytes):1271 (10168 megabytes)
            (d_total, d_used, d_avail) = re.findall(r'(\d+) megabytes',
                                                    output[0])
            disk_total += int(d_total)
            disk_used += int(d_used)
            disk_avail += int(d_avail)

        return {'disk_total': disk_total,
                'disk_used': disk_used,
                'disk_avail': disk_avail}

    def run_command(self, cmd, check_exit_code=True):
        """Run a remote command using an active ssh connection.

        :param command: String with the command to run.
        """
        self._set_connection()
        stdout, stderr = utils.ssh_execute(self._connection, cmd,
                                           check_exit_code=check_exit_code)
        return stdout.strip().splitlines()

    def run_command_as_root(self, command, check_exit_code=True):
        """Run a remote command as root using an active ssh connection.

        :param command: List of commands.
        """
        self._set_connection()
        stdout, stderr = common.ssh_command_as_root(
            self._connection, command, check_exit_code=check_exit_code)
        return stdout.read().splitlines()


class IVMOperator(BaseOperator):
    """Integrated Virtualization Manager (IVM) Operator.

    Runs specific commands on an IVM managed system.
    """

    def __init__(self, ivm_connection):
        self.command = command.IVMCommand()
        BaseOperator.__init__(self, ivm_connection)
