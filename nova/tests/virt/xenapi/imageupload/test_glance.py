# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC.
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


import mox

from nova import context
from nova import test
from nova.virt.xenapi.imageupload import glance
from nova.virt.xenapi import vm_utils


class TestGlanceStore(test.TestCase):
    def setUp(self):
        super(TestGlanceStore, self).setUp()
        self.store = glance.GlanceStore()
        self.mox = mox.Mox()

    def tearDown(self):
        super(TestGlanceStore, self).tearDown()

    def test_upload_image(self):

        def fake_get_sr_path(*_args, **_kwargs):
            return None

        self.stubs.Set(vm_utils, 'get_sr_path', fake_get_sr_path)

        ctx = context.RequestContext('user', 'project', auth_token='foobar')
        properties = {
            'auto_disk_config': True,
            'os_type': 'default',
        }
        instance = {'uuid': 'blah'}
        instance.update(properties)

        params = {'vdi_uuids': None,
                  'image_id': None,
                  'glance_host': mox.IgnoreArg(),
                  'glance_port': mox.IgnoreArg(),
                  'glance_use_ssl': mox.IgnoreArg(),
                  'sr_path': mox.IgnoreArg(),
                  'auth_token': 'foobar',
                  'properties': properties}
        session = self.mox.CreateMockAnything()
        session.call_plugin_serialized('glance', 'upload_vhd', **params)
        self.mox.ReplayAll()

        self.store.upload_image(ctx, session, instance, None, None)

        self.mox.VerifyAll()
