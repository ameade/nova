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
import uuid

from nova import context
from nova.openstack.common import cfg
from nova import test
import nova.virt.xenapi.imageupload.glance_with_swift_bypass as swift
from nova.virt.xenapi import vm_utils


CONF = cfg.CONF


class TestStore(test.TestCase):
    def setUp(self):
        super(TestStore, self).setUp()
        self.mox = mox.Mox()
        self.image_service = self.mox.CreateMockAnything()
        self.store = swift.Store(image_service=self.image_service)
        self.flags(swift_store_user="user")
        self.flags(swift_store_key="password")
        self.flags(swift_store_container="the_container")

    def tearDown(self):
        super(TestStore, self).tearDown()

    def test_get_image_url_http(self):
        self.flags(swift_store_auth_address="http://localhost:5000/v2.0/")
        image_id = str(uuid.uuid4())
        expected = ("swift+http://user:password@localhost:5000/"
                    "v2.0/the_container/%s" % image_id)
        actual = self.store.get_image_url(image_id)
        self.assertEqual(actual, expected)

    def test_get_image_url_https(self):
        self.flags(swift_store_auth_address="https://localhost:5000/v2.0/")
        image_id = str(uuid.uuid4())
        expected = ("swift+https://user:password@localhost:5000/"
                    "v2.0/the_container/%s" % image_id)
        actual = self.store.get_image_url(image_id)
        self.assertEqual(actual, expected)

    def test_get_image_url_multitenant(self):
        self.flags(swift_store_multitenant=True)
        self.store.store_url = 'http://localhost:8080/v2.0'

        image_id = str(uuid.uuid4())
        expected = ("swift+http://localhost:8080/"
                    "v2.0/the_container/%s" % image_id)
        actual = self.store.get_image_url(image_id)
        self.assertEqual(actual, expected)

    def test_upload_vhd_single_tenant(self):
        self.flags(swift_store_multitenant=False)

        sr_path = 'fake_sr_path'

        def fake_get_sr_path(*_args, **_kwargs):
            return sr_path

        self.stubs.Set(vm_utils, 'get_sr_path', fake_get_sr_path)

        image_id = 'fake_image_uuid'
        vdi_uuids = ['fake_vdi_uuid']
        ctx = None
        large_object_size = CONF.swift_store_large_object_size
        large_chunk_size = CONF.swift_store_large_object_chunk_size
        create_container = CONF.swift_store_create_container_on_put

        params = {'vdi_uuids': vdi_uuids,
                  'image_id': image_id,
                  'sr_path': sr_path,
                  'swift_enable_snet': CONF.swift_enable_snet,
                  'swift_store_auth_version': CONF.swift_store_auth_version,
                  'swift_store_container': CONF.swift_store_container,
                  'swift_store_large_object_size': large_object_size,
                  'swift_store_large_object_chunk_size': large_chunk_size,
                  'swift_store_create_container_on_put': create_container,
                  # Single tenant specific kwargs
                  'swift_store_user': CONF.swift_store_user,
                  'swift_store_key': CONF.swift_store_key,
                  'full_auth_address': CONF.swift_store_auth_address,
                 }
        session = self.mox.CreateMockAnything()
        session.call_plugin_serialized('swift', 'upload_vhd', **params)
        self.mox.ReplayAll()

        self.store.upload_vhd(ctx, session, {}, vdi_uuids, image_id)

        self.mox.VerifyAll()

    def test_upload_vhd_multitenant(self):
        self.flags(swift_store_multitenant=True)

        sr_path = 'fake_sr_path'

        def fake_get_sr_path(*_args, **_kwargs):
            return sr_path

        self.stubs.Set(vm_utils, 'get_sr_path', fake_get_sr_path)

        image_id = 'fake_image_uuid'
        vdi_uuids = ['fake_vdi_uuid']
        ctx = context.RequestContext('user', 'project', auth_token='foobar')
        large_object_size = CONF.swift_store_large_object_size
        large_chunk_size = CONF.swift_store_large_object_chunk_size
        create_container = CONF.swift_store_create_container_on_put

        params = {'vdi_uuids': vdi_uuids,
                  'image_id': image_id,
                  'sr_path': sr_path,
                  'swift_enable_snet': CONF.swift_enable_snet,
                  'swift_store_auth_version': CONF.swift_store_auth_version,
                  'swift_store_container': CONF.swift_store_container,
                  'swift_store_large_object_size': large_object_size,
                  'swift_store_large_object_chunk_size': large_chunk_size,
                  'swift_store_create_container_on_put': create_container,
                  # multitenant specific kwargs
                  'storage_url': None,
                  'token': 'foobar',
                 }
        session = self.mox.CreateMockAnything()
        session.call_plugin_serialized('swift', 'upload_vhd', **params)
        self.mox.ReplayAll()

        self.store.upload_vhd(ctx, session, {}, vdi_uuids, image_id)

        self.mox.VerifyAll()

    def test_upload_image(self):

        image_id = 'fake_image_uuid'
        image_meta = {'etag': 'ae83dbf9987e',
                      'image_size': '3',
                      'disk_format': 'vhd',
                      'container_format': 'ovf'}

        def fake_upload_vhd(*_args, **_kwargs):
            return image_meta

        self.stubs.Set(self.store, 'upload_vhd', fake_upload_vhd)
        ctx = context.RequestContext('user', 'project', auth_token='foobar')

        session = None
        vdi_uuids = None
        expected_image_meta = {'checksum': 'ae83dbf9987e',
                               'size': '3',
                               'location': self.store.get_image_url(image_id),
                               'disk_format': 'vhd',
                               'container_format': 'ovf'}
        self.image_service.update(ctx, image_id, expected_image_meta,
                                  purge_props=False)

        self.mox.ReplayAll()

        self.store.upload_image(ctx, session, {}, vdi_uuids, image_id)
        self.mox.VerifyAll()

    def test_upload_image_error(self):

        def fake_upload_vhd(*_args, **_kwargs):
            raise Exception()

        self.stubs.Set(self.store, 'upload_vhd', fake_upload_vhd)
        ctx = context.RequestContext('user', 'project', auth_token='foobar')

        image_id = 'fake_image_uuid'
        session = None
        vdi_uuids = None
        self.image_service.delete(ctx, image_id)

        self.mox.ReplayAll()

        self.store.upload_image(ctx, session, {}, vdi_uuids, image_id)
        self.mox.VerifyAll()
