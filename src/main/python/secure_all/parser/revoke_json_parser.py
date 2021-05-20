"""parser for input key files according to RF2"""

from secure_all.parser.json_parser import JsonParser

class RevokeJsonParser(JsonParser):
    """parser for input revoke files containing a RevokeKey request"""
    #pylint: disable=too-few-public-methods
    REVOCATION = "Revocation"
    KEY = "Key"
    REASON = "Reason"
    _key_list =  [ KEY, REVOCATION, REASON ]
