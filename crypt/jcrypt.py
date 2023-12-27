from typing import Any
import warnings
import json
from typing import TypeVar, Union, List, Dict, Any

from .crypt import Crypt


_JSONParseable = TypeVar("_JSONParseable", Union[List[Any], Dict[str, Any], str, int, float, bool, None])


class JCrypt(Crypt):
    """
    Encrypts and decrypts JSON parsable objects.

    :attr rsa_key_strength: rsa encryption key strength. Default to 1
    :attr sign_and_verify_key: whether to sign and verify the fernet key on encryption and decryption. Default to True.
    :attr suppress_warnings: whether to suppress all warnings during encryption and decryption.

    NOTE: The higher the encryption key strength, the longer it takes to encrypt and decrypt but the more secure it is.
    There a three levels
    """
    suppress_warnings = False

    def encrypt(self, obj: _JSONParseable) -> _JSONParseable:
        encrypted_obj = super().encrypt(obj)
        return json.loads(json.dumps(encrypted_obj))
  
    
    def decrypt(self, object_: _JSONParseable) -> _JSONParseable:
        decrypted_obj = super().decrypt(object_)
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
