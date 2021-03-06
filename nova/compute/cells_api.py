# Copyright (c) 2012 Rackspace Hosting
# All Rights Reserved.
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

"""Compute API that proxies via Cells Service"""

from nova import block_device
from nova.cells import rpcapi as cells_rpcapi
from nova.compute import api as compute_api
from nova.compute import task_states
from nova.compute import vm_states
from nova import exception
from nova.openstack.common import excutils
from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)


check_instance_state = compute_api.check_instance_state
wrap_check_policy = compute_api.wrap_check_policy
check_policy = compute_api.check_policy
check_instance_lock = compute_api.check_instance_lock


def validate_cell(fn):
    def _wrapped(self, context, instance, *args, **kwargs):
        self._validate_cell(instance, fn.__name__)
        return fn(self, context, instance, *args, **kwargs)
    _wrapped.__name__ = fn.__name__
    return _wrapped


class ComputeRPCAPINoOp(object):
    def __getattr__(self, key):
        def _noop_rpc_wrapper(*args, **kwargs):
            return None
        return _noop_rpc_wrapper


class SchedulerRPCAPIRedirect(object):
    def __init__(self, cells_rpcapi_obj):
        self.cells_rpcapi = cells_rpcapi_obj

    def __getattr__(self, key):
        def _noop_rpc_wrapper(*args, **kwargs):
            return None
        return _noop_rpc_wrapper

    def run_instance(self, context, **kwargs):
        self.cells_rpcapi.schedule_run_instance(context, **kwargs)


class ComputeCellsAPI(compute_api.API):
    def __init__(self, *args, **kwargs):
        super(ComputeCellsAPI, self).__init__(*args, **kwargs)
        self.cells_rpcapi = cells_rpcapi.CellsAPI()
        # Avoid casts/calls directly to compute
        self.compute_rpcapi = ComputeRPCAPINoOp()
        # Redirect scheduler run_instance to cells.
        self.scheduler_rpcapi = SchedulerRPCAPIRedirect(self.cells_rpcapi)

    def _cell_read_only(self, cell_name):
        """Is the target cell in a read-only mode?"""
        # FIXME(comstud): Add support for this.
        return False

    def _validate_cell(self, instance, method):
        cell_name = instance['cell_name']
        if not cell_name:
            raise exception.InstanceUnknownCell(
                    instance_uuid=instance['uuid'])
        if self._cell_read_only(cell_name):
            raise exception.InstanceInvalidState(
                    attr="vm_state",
                    instance_uuid=instance['uuid'],
                    state="temporary_readonly",
                    method=method)

    def _cast_to_cells(self, context, instance, method, *args, **kwargs):
        instance_uuid = instance['uuid']
        cell_name = instance['cell_name']
        if not cell_name:
            raise exception.InstanceUnknownCell(instance_uuid=instance_uuid)
        self.cells_rpcapi.cast_compute_api_method(context, cell_name,
                method, instance_uuid, *args, **kwargs)

    def _call_to_cells(self, context, instance, method, *args, **kwargs):
        instance_uuid = instance['uuid']
        cell_name = instance['cell_name']
        if not cell_name:
            raise exception.InstanceUnknownCell(instance_uuid=instance_uuid)
        return self.cells_rpcapi.call_compute_api_method(context, cell_name,
                method, instance_uuid, *args, **kwargs)

    def _check_requested_networks(self, context, requested_networks):
        """Override compute API's checking of this.  It'll happen in
        child cell
        """
        return

    def _validate_image_href(self, context, image_href):
        """Override compute API's checking of this.  It'll happen in
        child cell
        """
        return

    def _create_image(self, context, instance, name, image_type,
            backup_type=None, rotation=None, extra_properties=None):
        if backup_type:
            return self._call_to_cells(context, instance, 'backup',
                    name, backup_type, rotation,
                    extra_properties=extra_properties)
        else:
            return self._call_to_cells(context, instance, 'snapshot',
                    name, extra_properties=extra_properties)

    def create(self, *args, **kwargs):
        """We can use the base functionality, but I left this here just
        for completeness.
        """
        return super(ComputeCellsAPI, self).create(*args, **kwargs)

    @validate_cell
    def update(self, context, instance, **kwargs):
        """Update an instance."""
        rv = super(ComputeCellsAPI, self).update(context,
                instance, **kwargs)
        # We need to skip vm_state/task_state updates... those will
        # happen when via a a _cast_to_cells for running a different
        # compute api method
        kwargs_copy = kwargs.copy()
        kwargs_copy.pop('vm_state', None)
        kwargs_copy.pop('task_state', None)
        if kwargs_copy:
            try:
                self._cast_to_cells(context, instance, 'update',
                        **kwargs_copy)
            except exception.InstanceUnknownCell:
                pass
        return rv

    def _local_delete(self, context, instance, bdms):
        # This will get called for every delete in the API cell
        # because _delete() in compute/api.py will not find a
        # service when checking if it's up.
        # We need to only take action if there's no cell_name.  Our
        # overrides of delete() and soft_delete() will take care of
        # the rest.
        cell_name = instance['cell_name']
        if not cell_name:
            return super(ComputeCellsAPI, self)._local_delete(context,
                    instance, bdms)

    def soft_delete(self, context, instance):
        self._handle_cell_delete(context, instance,
                super(ComputeCellsAPI, self).soft_delete, 'soft_delete')

    def delete(self, context, instance):
        self._handle_cell_delete(context, instance,
                super(ComputeCellsAPI, self).delete, 'delete')

    def _handle_cell_delete(self, context, instance, method, method_name):
        """Terminate an instance."""
        # We can't use the decorator because we have special logic in the
        # case we don't know the cell_name...
        cell_name = instance['cell_name']
        if cell_name and self._cell_read_only(cell_name):
            raise exception.InstanceInvalidState(
                    attr="vm_state",
                    instance_uuid=instance['uuid'],
                    state="temporary_readonly",
                    method=method_name)
        method(context, instance)
        try:
            self._cast_to_cells(context, instance, method_name)
        except exception.InstanceUnknownCell:
            # If there's no cell, there's also no host... which means
            # the instance was destroyed from the DB here.  Let's just
            # broadcast a message down to all cells and hope this ends
            # up resolving itself...  Worse case.. the instance will
            # show back up again here.
            delete_type = method == 'soft_delete' and 'soft' or 'hard'
            self.cells_rpcapi.instance_delete_everywhere(context,
                    instance['uuid'], delete_type)

    @validate_cell
    def restore(self, context, instance):
        """Restore a previously deleted (but not reclaimed) instance."""
        super(ComputeCellsAPI, self).restore(context, instance)
        self._cast_to_cells(context, instance, 'restore')

    @validate_cell
    def force_delete(self, context, instance):
        """Force delete a previously deleted (but not reclaimed) instance."""
        super(ComputeCellsAPI, self).force_delete(context, instance)
        self._cast_to_cells(context, instance, 'force_delete')

    @validate_cell
    def stop(self, context, instance, do_cast=True):
        """Stop an instance."""
        super(ComputeCellsAPI, self).stop(context, instance)
        if do_cast:
            self._cast_to_cells(context, instance, 'stop', do_cast=True)
        else:
            return self._call_to_cells(context, instance, 'stop',
                    do_cast=False)

    @validate_cell
    def start(self, context, instance):
        """Start an instance."""
        super(ComputeCellsAPI, self).start(context, instance)
        self._cast_to_cells(context, instance, 'start')

    @validate_cell
    def reboot(self, context, instance, *args, **kwargs):
        """Reboot the given instance."""
        super(ComputeCellsAPI, self).reboot(context, instance,
                *args, **kwargs)
        self._cast_to_cells(context, instance, 'reboot', *args,
                **kwargs)

    @validate_cell
    def rebuild(self, context, instance, *args, **kwargs):
        """Rebuild the given instance with the provided attributes."""
        super(ComputeCellsAPI, self).rebuild(context, instance, *args,
                **kwargs)
        self._cast_to_cells(context, instance, 'rebuild', *args, **kwargs)

    @check_instance_state(vm_state=[vm_states.RESIZED])
    @validate_cell
    def revert_resize(self, context, instance):
        """Reverts a resize, deleting the 'new' instance in the process."""
        # NOTE(markwash): regular api manipulates the migration here, but we
        # don't have access to it. So to preserve the interface just update the
        # vm and task state.
        self.update(context, instance,
                    task_state=task_states.RESIZE_REVERTING)
        self._cast_to_cells(context, instance, 'revert_resize')

    @check_instance_state(vm_state=[vm_states.RESIZED])
    @validate_cell
    def confirm_resize(self, context, instance):
        """Confirms a migration/resize and deletes the 'old' instance."""
        # NOTE(markwash): regular api manipulates migration here, but we don't
        # have the migration in the api database. So to preserve the interface
        # just update the vm and task state without calling super()
        self.update(context, instance, task_state=None,
                    vm_state=vm_states.ACTIVE)
        self._cast_to_cells(context, instance, 'confirm_resize')

    @check_instance_state(vm_state=[vm_states.ACTIVE, vm_states.STOPPED],
                          task_state=[None])
    @validate_cell
    def resize(self, context, instance, *args, **kwargs):
        """Resize (ie, migrate) a running instance.

        If flavor_id is None, the process is considered a migration, keeping
        the original flavor_id. If flavor_id is not None, the instance should
        be migrated to a new host and resized to the new flavor_id.
        """
        super(ComputeCellsAPI, self).resize(context, instance, *args,
                **kwargs)
        # FIXME(comstud): pass new instance_type object down to a method
        # that'll unfold it
        self._cast_to_cells(context, instance, 'resize', *args, **kwargs)

    @validate_cell
    def add_fixed_ip(self, context, instance, *args, **kwargs):
        """Add fixed_ip from specified network to given instance."""
        super(ComputeCellsAPI, self).add_fixed_ip(context, instance,
                *args, **kwargs)
        self._cast_to_cells(context, instance, 'add_fixed_ip',
                *args, **kwargs)

    @validate_cell
    def remove_fixed_ip(self, context, instance, *args, **kwargs):
        """Remove fixed_ip from specified network to given instance."""
        super(ComputeCellsAPI, self).remove_fixed_ip(context, instance,
                *args, **kwargs)
        self._cast_to_cells(context, instance, 'remove_fixed_ip',
                *args, **kwargs)

    @validate_cell
    def pause(self, context, instance):
        """Pause the given instance."""
        super(ComputeCellsAPI, self).pause(context, instance)
        self._cast_to_cells(context, instance, 'pause')

    @validate_cell
    def unpause(self, context, instance):
        """Unpause the given instance."""
        super(ComputeCellsAPI, self).unpause(context, instance)
        self._cast_to_cells(context, instance, 'unpause')

    def set_host_enabled(self, context, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        # FIXME(comstud): Since there's no instance here, we have no
        # idea which cell should be the target.
        pass

    def host_power_action(self, context, host, action):
        """Reboots, shuts down or powers up the host."""
        # FIXME(comstud): Since there's no instance here, we have no
        # idea which cell should be the target.
        pass

    def get_diagnostics(self, context, instance):
        """Retrieve diagnostics for the given instance."""
        # FIXME(comstud): Cache this?
        # Also: only calling super() to get state/policy checking
        super(ComputeCellsAPI, self).get_diagnostics(context, instance)
        return self._call_to_cells(context, instance, 'get_diagnostics')

    @validate_cell
    def suspend(self, context, instance):
        """Suspend the given instance."""
        super(ComputeCellsAPI, self).suspend(context, instance)
        self._cast_to_cells(context, instance, 'suspend')

    @validate_cell
    def resume(self, context, instance):
        """Resume the given instance."""
        super(ComputeCellsAPI, self).resume(context, instance)
        self._cast_to_cells(context, instance, 'resume')

    @validate_cell
    def rescue(self, context, instance, rescue_password=None):
        """Rescue the given instance."""
        super(ComputeCellsAPI, self).rescue(context, instance,
                rescue_password=rescue_password)
        self._cast_to_cells(context, instance, 'rescue',
                rescue_password=rescue_password)

    @validate_cell
    def unrescue(self, context, instance):
        """Unrescue the given instance."""
        super(ComputeCellsAPI, self).unrescue(context, instance)
        self._cast_to_cells(context, instance, 'unrescue')

    @validate_cell
    def set_admin_password(self, context, instance, password=None):
        """Set the root/admin password for the given instance."""
        super(ComputeCellsAPI, self).set_admin_password(context, instance,
                password=password)
        self._cast_to_cells(context, instance, 'set_admin_password',
                password=password)

    @validate_cell
    def inject_file(self, context, instance, *args, **kwargs):
        """Write a file to the given instance."""
        super(ComputeCellsAPI, self).inject_file(context, instance, *args,
                **kwargs)
        self._cast_to_cells(context, instance, 'inject_file', *args, **kwargs)

    @wrap_check_policy
    @validate_cell
    def get_vnc_console(self, context, instance, console_type):
        """Get a url to a VNC Console."""
        if not instance['host']:
            raise exception.InstanceNotReady(instance_id=instance['uuid'])

        connect_info = self._call_to_cells(context, instance,
                'get_vnc_connect_info', console_type)

        self.consoleauth_rpcapi.authorize_console(context,
                connect_info['token'], console_type, connect_info['host'],
                connect_info['port'], connect_info['internal_access_path'])
        return {'url': connect_info['access_url']}

    @validate_cell
    def get_console_output(self, context, instance, *args, **kwargs):
        """Get console output for an an instance."""
        # NOTE(comstud): Calling super() just to get policy check
        super(ComputeCellsAPI, self).get_console_output(context, instance,
                *args, **kwargs)
        return self._call_to_cells(context, instance, 'get_console_output',
                *args, **kwargs)

    def lock(self, context, instance):
        """Lock the given instance."""
        super(ComputeCellsAPI, self).lock(context, instance)
        self._cast_to_cells(context, instance, 'lock')

    def unlock(self, context, instance):
        """Unlock the given instance."""
        super(ComputeCellsAPI, self).lock(context, instance)
        self._cast_to_cells(context, instance, 'unlock')

    @validate_cell
    def reset_network(self, context, instance):
        """Reset networking on the instance."""
        super(ComputeCellsAPI, self).reset_network(context, instance)
        self._cast_to_cells(context, instance, 'reset_network')

    @validate_cell
    def inject_network_info(self, context, instance):
        """Inject network info for the instance."""
        super(ComputeCellsAPI, self).inject_network_info(context, instance)
        self._cast_to_cells(context, instance, 'inject_network_info')

    @wrap_check_policy
    @validate_cell
    def attach_volume(self, context, instance, volume_id, device=None):
        """Attach an existing volume to an existing instance."""
        if device and not block_device.match_device(device):
            raise exception.InvalidDevicePath(path=device)
        device = self.compute_rpcapi.reserve_block_device_name(
            context, device=device, instance=instance, volume_id=volume_id)
        try:
            volume = self.volume_api.get(context, volume_id)
            self.volume_api.check_attach(context, volume)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.block_device_mapping_destroy_by_instance_and_device(
                        context, instance['uuid'], device)
        self._cast_to_cells(context, instance, 'attach_volume',
                volume_id, device)

    @check_instance_lock
    @validate_cell
    def _detach_volume(self, context, instance, volume_id):
        """Detach a volume from an instance."""
        check_policy(context, 'detach_volume', instance)

        volume = self.volume_api.get(context, volume_id)
        self.volume_api.check_detach(context, volume)
        self._cast_to_cells(context, instance, 'detach_volume',
                volume_id)

    @wrap_check_policy
    @validate_cell
    def associate_floating_ip(self, context, instance, address):
        """Makes calls to network_api to associate_floating_ip.

        :param address: is a string floating ip address
        """
        self._cast_to_cells(context, instance, 'associate_floating_ip',
                address)

    @validate_cell
    def delete_instance_metadata(self, context, instance, key):
        """Delete the given metadata item from an instance."""
        super(ComputeCellsAPI, self).delete_instance_metadata(context,
                instance, key)
        self._cast_to_cells(context, instance, 'delete_instance_metadata',
                key)

    @wrap_check_policy
    @validate_cell
    def update_instance_metadata(self, context, instance,
                                 metadata, delete=False):
        rv = super(ComputeCellsAPI, self).update_instance_metadata(context,
                instance, metadata, delete=delete)
        try:
            self._cast_to_cells(context, instance,
                    'update_instance_metadata',
                    metadata, delete=delete)
        except exception.InstanceUnknownCell:
            pass
        return rv
