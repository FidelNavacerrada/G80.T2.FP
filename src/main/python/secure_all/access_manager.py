"""Module AccessManager with AccessManager Class """

from secure_all.data.access_key import AccessKey
from secure_all.data.access_request import AccessRequest
from secure_all.data.revoke_key import RevokeKey


class AccessManager:
    """AccessManager class, manages the access to a building implementing singleton """
    #pylint: disable=too-many-arguments,no-self-use,invalid-name, too-few-public-methods
    class __AccessManager:
        """Class for providing the methods for managing the access to a building"""

        def request_access_code( self, id_card, name_surname, access_type, email_address, days ):
            """ this method give access to the building"""
            my_request = AccessRequest(id_card, name_surname, access_type, email_address, days)
            a = my_request.access_code
            my_request.store_request(a)
            return a

        def get_access_key( self, keyfile ):
            """Returns the access key for the access code & dni received in a json file"""
            my_key = AccessKey.create_key_from_file(keyfile)
            my_key.store_keys()
            return my_key.key

        def open_door( self, key ):
            """Opens the door if the key is valid an it is not expired"""

            my_door = AccessKey.create_key_from_id(key)
            if my_door.is_valid():
                my_door.store_door()
            return AccessKey.create_key_from_id(key).is_valid()

        def revoke_key(self,filepath):
            my_revoke=RevokeKey.create_revoke_from_file(filepath)
            return my_revoke.revoke_manager()



    __instance = None

    def __new__( cls ):
        if not AccessManager.__instance:
            AccessManager.__instance = AccessManager.__AccessManager()
        return AccessManager.__instance
