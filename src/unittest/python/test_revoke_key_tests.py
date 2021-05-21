import unittest
from pathlib import Path
from secure_all import AccessManager, AccessManagementException, \
    AccessKey, JSON_FILES_PATH, KeysJsonStore, RequestJsonStore
from secure_all.storage.door_requests import DoorRequest
from secure_all.storage.revoke_store import RevoqueJsonStore

class MyTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        """class method setup"""
        # first af all, i introduce all value tha I need for the estructural testing
        # remove the old storeKeys
        requests_store = RequestJsonStore()
        keys_store = KeysJsonStore()
        door_store = DoorRequest()
        door_store.empty_store()
        requests_store.empty_store()
        keys_store.empty_store()
        rekest_store = RevoqueJsonStore()
        rekest_store.empty_store()
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

    def test_revoke_key_ok_1(self):
        """Test para validar"""

        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke\good_1.json"

        my_mails = AccessManager().revoke_key(my_file)
        self.assertEqual(["mail1@uc3m.es", "mail2@uc3m.es"], my_mails)

    def test_revoke_key_ok_2(self):
        """Test para validar , con """
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke\good_2.json"

        my_mails = AccessManager().revoke_key(my_file)
        self.assertEqual(["mail1@uc3m.es","mail2@uc3m.es"], my_mails)


    def test_revoke_key_repetida(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke\_revok_repetida.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("La clave fue revocada previamente por este método.",cm.exception.message)

    def test_revoke_key_fichero_vacio(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/fichero_vacio.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format",cm.exception.message)

    def test_revoke_key_no_inicio_objeto(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_inicio_objeto.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format",cm.exception.message)

    def test_revoke_key_inicio_repetido(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/inicio_repetido.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format",cm.exception.message)

    def test_revoke_key_no_datos(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_datos.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong label",cm.exception.message)

    def test_revoke_key_datos_repetidos(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/datos_repetidos.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format",cm.exception.message)

    def test_revoke_key_no_fin_objeto(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_fin_objeto.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format",cm.exception.message)

    def test_revoke_key_doble_fin_objeto(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_fin_objeto.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_fichero(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_fichero.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_campo_1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_campo_1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_no_campo_1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_campo_1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_no_separador_1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_separador_1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_separador_1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_separador_1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_campo_2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_campo_2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_no_campo_2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_campo_2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_no_separador_2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_separador_2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_separador_2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_separador_2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_non_campo3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/non_campo3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_campo_3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_campo_3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_e1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_e1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_igualdad1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_igualdad1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_vd1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_vd1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_e1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_e1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_igualdad1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_igualdad1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_vd1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_vd1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_valor1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_valor1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("La clave recibida no existe.", cm.exception.message)

    def test_revoke_key_doble_valor_e1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_valor_e1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong label", cm.exception.message)

    def test_revoke_key_dobles_comillas_e1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/dobles_comillas_e1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_dobles_comillas_vd1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/dobles_comillas_vd1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_comillas_e1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_comillas_e1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_comillas_vd1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_comillas_vd1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_valor1(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_valor1.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("La clave recibida no existe.", cm.exception.message)

    def test_revoke_key_doble_comillas_e3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_comillas_e3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_comillas_vd3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_comillas_vd3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_e2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_e2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_e3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_e3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_i3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_i3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_igualdad2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_igualdad2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_valore3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_valore3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong label", cm.exception.message)

    def test_revoke_key_doble_vd2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_vd2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_doble_vd3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/doble_vd3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_no_comillas_e3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_comillas_e3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_no_comillas_vd3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_comillas_vd3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_no_valore3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/no_valore3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong label", cm.exception.message)

    def test_revoke_key_sin_comillas_e2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_comillas_e2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_dato3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_dato3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("La clave fue revocada previamente por este método.", cm.exception.message)

    def test_revoke_key_sin_e2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_e2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_e3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_e3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_igualdad2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_igualdad2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_sin_vd2(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_vd2.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("La clave fue revocada previamente por este método.", cm.exception.message)

    def test_revoke_key_sin_vd3(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/sin_vd3.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_noesjson(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/noesjson"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("JSON Decode Error - Wrong JSON Format", cm.exception.message)

    def test_revoke_key_clave_erronea(self):
        """Test para validar"""
        my_file = str(Path.home()) + "\PycharmProjects\G80.T2.FP\src\JsonFiles\JsonFiles_Revoke/clave_erronea.json"
        with self.assertRaises(AccessManagementException) as cm:
            AccessManager().revoke_key(my_file)
        self.assertEqual("La clave recibida no existe.", cm.exception.message)

if __name__ == '__main__':
    unittest.main()
