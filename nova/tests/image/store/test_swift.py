# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
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


import uuid

from nova.image.store import swift
from nova import test


class TestSwiftStore(test.TestCase):
    def setUp(self):
        super(TestSwiftStore, self).setUp()
        self.store = swift.SwiftStore()
        self.flags(swift_store_user="user")
        self.flags(swift_store_key="password")
        self.flags(swift_store_container="the_container")

    def tearDown(self):
        super(TestSwiftStore, self).tearDown()

    def test_get_location_http(self):
        self.flags(swift_store_auth_address="http://localhost:5000/v2.0/")
        image_id = str(uuid.uuid4())
        expected = ("swift+http://user:password@localhost:5000/"
                    "v2.0/the_container/%s" % image_id)
        actual = self.store.get_location(image_id)
        self.assertEqual(actual, expected)

    def test_get_location_https(self):
        self.flags(swift_store_auth_address="https://localhost:5000/v2.0/")
        image_id = str(uuid.uuid4())
        expected = ("swift+https://user:password@localhost:5000/"
                    "v2.0/the_container/%s" % image_id)
        actual = self.store.get_location(image_id)
        self.assertEqual(actual, expected)
