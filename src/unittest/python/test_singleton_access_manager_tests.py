"""Testing of Singleton in Access Manager"""

import unittest

from secure_all import AccessManager, KeysJsonStore, RequestJsonStore
from secure_all.data.attributes.attribute_dni import Dni
from secure_all.storage.door_requests import DoorRequest
from secure_all.storage.revoke_store import RevoqueJsonStore

class MyTestCase(unittest.TestCase):
    """Test case for the singletons"""
    def test_singleton_access_manager( self ):
        """Instance the three singletons and test they're equal
            Instance objects from non singleton class and test they're differet"""
        access_manager_1 = AccessManager()
        access_manager_2 = AccessManager()
        access_manager_3 = AccessManager()

        self.assertEqual(access_manager_1, access_manager_2)
        self.assertEqual(access_manager_2, access_manager_3)
        self.assertEqual(access_manager_3, access_manager_1)

        request_json_store_1 = RequestJsonStore()
        request_json_store_2 = RequestJsonStore()
        request_json_store_3 = RequestJsonStore()

        self.assertEqual(request_json_store_1, request_json_store_2)
        self.assertEqual(request_json_store_2, request_json_store_3)
        self.assertEqual(request_json_store_3, request_json_store_1)

        keys_json_store_1 = KeysJsonStore()
        keys_json_store_2 = KeysJsonStore()
        keys_json_store_3 = KeysJsonStore()

        self.assertEqual(keys_json_store_1, keys_json_store_2)
        self.assertEqual(keys_json_store_2, keys_json_store_3)
        self.assertEqual(keys_json_store_3, keys_json_store_1)

        revoke_key_1 = RevoqueJsonStore()
        revoke_key_2 = RevoqueJsonStore()
        revoke_key_3 = RevoqueJsonStore()

        self.assertEqual( revoke_key_1,  revoke_key_2)
        self.assertEqual( revoke_key_2,  revoke_key_3)
        self.assertEqual( revoke_key_3,  revoke_key_1)

        door_request_1 = DoorRequest()
        door_request_2 = DoorRequest()
        door_request_3 = DoorRequest()

        self.assertEqual(door_request_1, door_request_2)
        self.assertEqual(door_request_2, door_request_3)
        self.assertEqual(door_request_3, door_request_1)

        #probamos ahora que dos clases sin singleton devuelven
        #instancias distintas. Por ejemplo con DNI

        dni_1 = Dni("12345678Z")
        dni_2 = Dni("12345678Z")

        self.assertNotEqual(dni_1, dni_2)

if __name__ == '__main__':
    unittest.main()
