from typing import TypeVar, List, Dict, Any

from .base import Encryptable
from .object import ObjectCrypt


JSONParsable = TypeVar("JSONParsable", List[Any], Dict[str, Any], str, int, float, bool, None)


class JSONCrypt(ObjectCrypt):
    """
    Encrypts and decrypts objects into JSON parsable objects.
    """
    def encrypt(self, obj: Encryptable) -> JSONParsable:
        return super().encrypt(obj)
  
    
    def decrypt(self, encrypted_obj: JSONParsable) -> Encryptable:
        return super().decrypt(encrypted_obj)


    # Override `encrypt_tuple` and `encrypt_set` methods to return a list. sets and tuples are not JSON parsable
    def encrypt_tuple(self, tuple_: tuple) -> List[Any]:
        """
        Encrypts a tuple content

        :param tuple_: tuple containing contents to be encrypted
        :return: list containing encrypted content
        """
        if not isinstance(tuple_, tuple):
            raise TypeError(tuple_)
        return self.encrypt_list(list(tuple_))


    def encrypt_set(self, set_: set) -> List[Any]:
        """
        Encrypts a set content

        :param set_: set containing contents to be encrypted
        :return: list containing encrypted content
        """
        if not isinstance(set_, set):
            raise TypeError(set_)
        return self.encrypt_list(list(set_))
