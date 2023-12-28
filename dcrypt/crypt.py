import pickle
from typing import Any, Dict, TypeVar, List
import base64

from .tcrypt import TCrypt
from .exceptions import EncryptionError, DecryptionError

_SupportsCrypt = TypeVar("_SupportsCrypt", str, int, float, bool, bytes, list, tuple, set, dict, None)



class Crypt(TCrypt):
    """
    Encrypts and decrypts text and Python objects using Fernet + RSA Encryption

    :attr rsa_key_strength: rsa encryption key strength. Default to 1.
    :attr sign_and_verify_key: whether to sign and verify the fernet key on encryption and decryption. Default to True.

    NOTE: The higher the encryption key strength, the longer it takes to encrypt and decrypt but the more secure it is.
    There a three levels. Empty strings and None are not encrypted.
    """

    def encrypt(self, obj: _SupportsCrypt) -> _SupportsCrypt | Any:
        """
        Encrypts an object.

        :param obj: Object to be encrypted
        :return: encrypted Python object
        """
        if obj is not None and obj != "":
            try:
                return getattr(self, f"encrypt_{type(obj).__name__.lower()}")(obj)
            except AttributeError:
                return self._encrypt_object(obj)
            except Exception as exc:
                raise EncryptionError(exc)
        return obj


    def decrypt(self, enc: _SupportsCrypt) -> _SupportsCrypt | Any:
        """
        Decrypts encrypted object.

        :param enc: Object to be decrypted
        :return: decrypted Python object
        """
        if enc is not None and enc != "":
            try:
                return getattr(self, f"decrypt_{type(enc).__name__.lower()}")(enc)
            except Exception as exc:
                raise DecryptionError(exc)
        return enc


    def encrypt_str(self, string: str) -> str:
        """
        Encrypts a string using the encryption key.

        :param string: string to be encrypted
        :return: encrypted string and signature
        """
        if not isinstance(string, str):
            raise TypeError("string must be a string")
        r = super().encrypt(string)
        return r


    def decrypt_str(self, cipher_string: str):
        """
        Decrypts an encrypted string using the encryption key.

        :param cipher_string: encrypted string to be decrypted
        :param signature: signature of the encrypted string
        :return: decrypted object
        """
        if not isinstance(cipher_string, str):
            raise TypeError("encrypted_string must be a string")

        type_ = None
        split = cipher_string.split('\u0000')
        if cipher_string.startswith(':ty-') and len(split) > 1:
            if len(split) == 2:
                type_, cipher_str = split
                r = super().decrypt(cipher_str)
            else:
                type_ = split[0]
                rem_cipher_str = "\u0000".join(split[1:])
                r = self.decrypt(rem_cipher_str)
        else:
            r = super().decrypt(cipher_string)

        if not type_:
            return str(r)
        if type_ == ":ty-ndbl:":
            return int(r)
        elif type_ == ":ty-dbl:":
            return float(r)
        elif type_ == ":ty-bln:":
            return bool(r)
        elif type_ == ":ty-b:":
            return base64.urlsafe_b64decode(r.encode())
        elif type_ == ":ty-obj:":
            return pickle.loads(r)


    def encrypt_int(self, int_: int):
        """
        Encrypts an integer

        :param int_: integer to be encrypted
        :return: encrypted integer as a string
        """
        if not isinstance(int_, int):
            raise TypeError(int_)
        e_int_ = self.encrypt_str(str(int_))
        return f":ty-ndbl:\u0000{e_int_}"


    def encrypt_float(self, float_: float):
        """
        Encrypts a float

        :param float_: float to be encrypted
        :return: encrypted float as a string
        """
        if not isinstance(float_, float):
            raise TypeError(float_)
        e_float_ = self.encrypt_str(str(float_))
        return f":ty-dbl:\u0000{e_float_}"


    def encrypt_bool(self, bool_: bool):
        """
        Encrypts a boolean

        :param bool_: boolean to be encrypted
        :return: encrypted boolean as a string
        """
        if not isinstance(bool_, bool):
            raise TypeError(bool_)
        e_bool_ = self.encrypt_str(str(bool_))
        return f":ty-bln:\u0000{e_bool_}"


    def encrypt_bytes(self, bytes_: bytes):
        """
        Encrypts a bytes content

        :param bytes_: bytes containing contents to be encrypted
        :return: string of encrypted bytes content
        """
        if not isinstance(bytes_, bytes):
            raise TypeError(bytes_)
        bytes_str = base64.urlsafe_b64encode(bytes_).decode()
        enc_bytes_str = self.encrypt(bytes_str)
        return f":ty-b:\u0000{enc_bytes_str}"


    def encrypt_tuple(self, tuple_: tuple):
        """
        Encrypts a tuple content

        :param tuple_: tuple containing contents to be encrypted
        :return: tuple with contents encrypted
        """
        if not isinstance(tuple_, tuple):
            raise TypeError(tuple_)
        return tuple(self.encrypt_list(list(tuple_)))
    

    def decrypt_tuple(self, cipher_tuple: tuple):
        """
        Decrypts a tuple of encrypted content

        :param cipher_tuple: tuple of encrypted content to be decrypted
        :return: tuple of decrypted content
        """
        if not isinstance(cipher_tuple, tuple):
            raise TypeError(cipher_tuple)
        return tuple(self.decrypt_list(list(cipher_tuple)))


    def encrypt_set(self, set_: set):
        """
        Encrypts a set content

        :param set_: set containing contents to be encrypted
        :return: set with contents encrypted
        """
        if not isinstance(set_, set):
            raise TypeError(set_)
        return set(self.encrypt_list(list(set_)))
    

    def decrypt_set(self, cipher_set: set):
        """
        Decrypts a set of encrypted content

        :param cipher_set: set of encrypted content to be decrypted
        :return: set of decrypted content
        """
        if not isinstance(cipher_set, set):
            raise TypeError(cipher_set)
        return set(self.decrypt_list(list(cipher_set)))


    def encrypt_list(self, list_: List):
        """
        Encrypts a list content

        :param secret: list containing contents to be encrypted
        :return: list of encrypted content
        """
        if not isinstance(list_, list):
            raise TypeError(list_)
        encrypted_list = []
        for item in list_:
            if item is not None and item != "":
                encrypted_item = self.encrypt(item)
                encrypted_list.append(encrypted_item)
            else:
                encrypted_list.append(item)
        return encrypted_list

    
    def decrypt_list(self, cipher_list: List):
        """
        Decrypts a list of encrypted content

        :param cipher_list: list of encrypted content to be decrypted
        :return: list of decrypted content
        """
        if not isinstance(cipher_list, list):
            raise TypeError(cipher_list)
        decrypted_list = []
        for item in cipher_list:
            if item is not None and item != "":
                decrypted_item = self.decrypt(item)
                decrypted_list.append(decrypted_item)
            else:
                decrypted_list.append(item)
        return decrypted_list

    
    def encrypt_dict(self, dict_: Dict):
        """
        Encrypts a dict content

        :param dict_: dictionary containing contents to be encrypted
        :return: dictionary of encrypted content
        """
        if not isinstance(dict_, dict):
            raise TypeError(dict_)
        encrypted_dict = {}
        for key, value in dict_.items():
            if value is not None and value != "":
                encrypted_value = self.encrypt(value)
                encrypted_dict[key] = encrypted_value
            else:
                encrypted_dict[key] = value
        return encrypted_dict

    
    def decrypt_dict(self, cipher_dict: Dict):
        """
        Decrypts dict with encrypted content

        :param cipher_list: list of encrypted content to be decrypted
        :return: list of decrypted content
        """
        if not isinstance(cipher_dict, dict):
            raise TypeError(cipher_dict)
        decrypted_dict = {}
        for key, value in cipher_dict.items():
            if value is not None and value != "":
                decrypted_value = self.decrypt(value)
                decrypted_dict[key] = decrypted_value
            else:
                decrypted_dict[key] = value
        return decrypted_dict  
    

    def _encrypt_object(self, object_: object):
        """
        Encrypts a Python class object

        :param object_: Python class object to be encrypted
        :return: encrypted Python class object
        """
        dumped_obj = pickle.dumps(object_)
        encrypted_obj = self.encrypt(dumped_obj)
        return f":ty-obj:\u0000{encrypted_obj}"


    
