import unittest
from pathlib import Path
from secure_all.access_manager import AccessManager
from secure_all import AccessManager, AccessManagementException, \
    AccessKey, JSON_FILES_PATH, KeysJsonStore, RequestJsonStore
from secure_all.storage.door_requests import DoorRequest

class MyTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        # first af all, i introduce all value tha I need for the estructural testing
        # remove the old storeKeys
        requests_store = RequestJsonStore()
        keys_store = KeysJsonStore()
        door_store = DoorRequest()
        door_store.empty_store()
        requests_store.empty_store()
        keys_store.empty_store()

        # introduce a key valid and not expired and guest
        my_manager = AccessManager()
        my_manager.request_access_code("05270358T", "Pedro Martin",
                                       "Resident", "uc3m@gmail.com", 0)

        my_manager.request_access_code("53935158C", "Marta Lopez",
                                       "Guest", "uc3m@gmail.com", 5)

        my_manager.get_access_key(JSON_FILES_PATH + "key_ok.json")

        # introduce a key valid and expiration date = 0 , resident
        my_manager.get_access_key(JSON_FILES_PATH + "key_ok3_resident.json")

        # introduce a key expirated, I need to change expiration date before to store the key
        my_manager.request_access_code("68026939T", "Juan Perez",
                                       "Guest", "expired@gmail.com", 2)
        # expected result 383a8eb306459919ef0dc819405f16a6
        # We generate the AccessKey for this AccessRequest
        my_key_expirated = AccessKey.create_key_from_file(JSON_FILES_PATH +
                                                          "key_ok_testing_expired.json")
        # We manipulate the expiration date to obtain an expired AccessKey
        my_key_expirated.expiration_date = 0
        my_key_expirated.store_keys()
    def test_access_key_ok_con_1_email_2(self):
        """Test para validar"""

        rekest_store = RequestJsonStore()
        rekest_store.empty_store()
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke\good_1.json"

        my_mails = AccessManager().revoke_key(my_file)
        self.assertEqual([
      "mail1@uc3m.es",
      "mail2@uc3m.es"
    ], my_mails)



    #def test_access_key_sin_campo_1_12(self):
     #   """Test para validar"""
      #  my_file = str(Path.home()) + " \PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke\good_1.json"
       # my_key = AccessManager()
        #with self.assertRaises(AccessManagementException) as cm:
         #   my_key.get_access_key(my_file)
        #self.assertEqual(cm.exception.message, "JSON-decode error - Wrong JSON format")
if __name__ == '__main__':
    unittest.main()
