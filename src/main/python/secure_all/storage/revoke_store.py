"""Implements the RequestsJSON Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class RevoqueJsonStore():
    """Extends JsonStore """
    class __RevoqueJsonStore(JsonStore):
        #pylint: disable=invalid-name
        ID_FIELD = "_RevokeKey__key"
        MAIL_LIST = "_AccessKey__notification_emails"
        REASON = "_AccessKey__reasons"

        _FILE_PATH = JSON_FILES_PATH + "storeRevokes.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, item):
            """Implementing the restrictions related to avoid duplicated keys"""
            #pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.revoke_key import RevokeKey

            if not isinstance(item,RevokeKey):
                raise AccessManagementException("El archivo de entrada tiene algún problema relacionado con su formato ocon su acceso.")

            if not self.find_item(item.getter_key) is None:
                raise AccessManagementException("La clave fue revocada previamente por este método.")

            return super().add_item(item.__dict__)

    __instance = None

    def __new__( cls ):
        if not RevoqueJsonStore.__instance:
            RevoqueJsonStore.__instance = RevoqueJsonStore.__RevoqueJsonStore()
        return RevoqueJsonStore.__instance

    def __getattr__ ( self, nombre ):
        return getattr(self.__instance, nombre)

    def __setattr__ ( self, nombre, valor ):
        return setattr(self.__instance, nombre, valor)
