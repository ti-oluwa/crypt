import warnings
import json
from typing import TypeVar, List, Dict, Any

from .cryptkey import CryptKey
from .base import Encryptable
from .object import ObjectCrypt


JSONParseable = TypeVar("JSONParseable", List[Any], Dict[str, Any], str, int, float, bool, None)


class JSONCrypt(ObjectCrypt):
    """
    Encrypts and decrypts objects into JSON parsable objects.
    """
    def __init__(self, key: CryptKey, suppress_warnings: bool = False):
        """
        Make a `JCrypt` object

        :param key: encryption key. Pass this if you already have an encryption key
        and just need to reconstruct the JCrypt object.
        :param suppress_warnings: suppress warnings. Default to False
        """
        super().__init__(key=key)
        self.suppress_warnings = suppress_warnings


    def encrypt(self, obj: Encryptable) -> JSONParseable:
        encrypted_obj = super().encrypt(obj)
        return json.loads(json.dumps(encrypted_obj))
  
    
    def decrypt(self, encrypted_obj: JSONParseable) -> Encryptable:
        decrypted_obj = super().decrypt(encrypted_obj)
        return json.loads(json.dumps(decrypted_obj))


    # Override `encrypt_tuple` and `encrypt_set` methods to return a list. sets and tuples are not JSON parsable
    def encrypt_tuple(self, tuple_: tuple) -> List[Any]:
        """
        Encrypts a tuple content

        :param tuple_: tuple containing contents to be encrypted
        :return: list containing encrypted content
        """
        if not self.suppress_warnings:
            warnings.warn("Tuples are not recommended for JSON", RuntimeWarning)
        if not isinstance(tuple_, tuple):
            raise TypeError(tuple_)
        return self.encrypt_list(list(tuple_))


    def encrypt_set(self, set_: set) -> List[Any]:
        """
        Encrypts a set content

        :param set_: set containing contents to be encrypted
        :return: list containing encrypted content
        """
        if not self.suppress_warnings:
            warnings.warn("Sets are not recommended for JSON", RuntimeWarning)
        if not isinstance(set_, set):
            raise TypeError(set_)
        return self.encrypt_list(list(set_))
