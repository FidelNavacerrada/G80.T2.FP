"""Class for parsing input JSON Files for the secure_all system"""
import json
from secure_all.exception.access_management_exception import AccessManagementException


class JsonParser():
    """Class for parsing input JSON Files for the secure_all system"""
    #pylint: disable=too-few-public-methods
    _key_list = []
    _KEY_ERROR_MESSAGE = "JSON Decode Error - Wrong label"
    _WRONG_FILE_OR_PATH = "Wrong file or file path"
    _WRONG_JSON_FORMAT= "JSON Decode Error - Wrong JSON Format"

    def __init__( self, file ):
        self._file = file
        self._json_content = self._parse_json_file()
        self._validate_json()

    def _parse_json_file (self):
        """read the file in json format format"""
        try:
            with open(self._file, "r", encoding="utf-8", newline="") as json_file:
                data = json.load(json_file)
        except FileNotFoundError as ex:
            raise AccessManagementException(self._WRONG_FILE_OR_PATH) from ex
        except json.JSONDecodeError as ex:
            raise AccessManagementException(self._WRONG_JSON_FORMAT) from ex
        return data

    def _validate_json( self ):
        """validate the json keys"""
        for key in self._key_list:
            if not key in self._json_content.keys():
                raise AccessManagementException(self._KEY_ERROR_MESSAGE)

    @property
    def json_content( self ):
        """Property for access the json content read from the json file"""
        return self._json_content
