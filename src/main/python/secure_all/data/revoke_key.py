from secure_all.parser.revoke_json_parser import RevokeJsonParser
from secure_all.storage.revoke_store import RevoqueJsonStore
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from datetime import datetime
from secure_all.data.attributes.attribute_key import Key


class RevokeKey():
    def __init__(self,key,revocation,reason):
        """class constructor"""
        self.__key = key
        self.__revocation = revocation
        self.__reason = reason

    def revoke_manager(self):
        """method to manager revokes"""
        self.find_key_store()
        self.stored_revoke()
        return self.find_email()

    def find_key_store(self):
        """method to find a key in storeKeys"""
        my_revoke = KeysJsonStore()
        x=my_revoke.find_item(self.getter_key)
        if not x:
            raise AccessManagementException("La clave recibida no existe.")
        expiration_day=x["_AccessKey__expiration_date"]
        self.expiration(expiration_day)

    def expiration(self,expire_day):
        """method to check an expiration"""
        if (expire_day < datetime.timestamp(datetime.utcnow()) and expire_day!=0):
            raise AccessManagementException("La clave recibida ha caducado.")


    def stored_revoke(self):
        """method to store a revoke"""
        my_store_revokes=RevoqueJsonStore()
        my_store_revokes.add_item(self)

    def find_email(self):
        """method to find emails"""
        my_emails=KeysJsonStore()
        email=my_emails.find_emails(self.getter_key)
        x=email["_AccessKey__notification_emails"]
        return x
    @property
    def getter_key(self):
        """property ytha return the key"""
        return self.__key

    @classmethod
    def create_revoke_from_file(cls, key_file):
        """Class method from creating an instance of AccessKey
        from the content of a file according to RF2"""
        revoke_key = RevokeJsonParser(key_file).json_content
        return cls(revoke_key[RevokeJsonParser.KEY],
                   revoke_key[RevokeJsonParser.REVOCATION],
                   revoke_key[RevokeJsonParser.REASON])


