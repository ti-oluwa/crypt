import pickle
from typing import Dict, Tuple, List, Set, Callable
import base64
import functools

from .base import Crypt, Encryptable, Decryptable
from .text import TextCrypt
from .exceptions import EncryptionError, DecryptionError



class ObjectCrypt(Crypt):
    """
    Encrypts and decrypts text and Python objects.
    """
    def __call__(self, func: Callable[..., Encryptable]) -> Callable[..., Decryptable]:
        """Encrypts the return value of the decorated function."""
        if not callable(func):
            raise TypeError("func must be callable")
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.encrypt(func(*args, **kwargs)) 
               
        return wrapper
    

    def encrypt(self, obj: Encryptable) -> Decryptable:
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


    def decrypt(self, encrypted_obj: Decryptable) -> Encryptable:
        """
        Decrypts encrypted object.

        :param encrypted_obj: Encrypted object to be decrypted
        :return: decrypted Python object
        """
        if encrypted_obj is not None and encrypted_obj != "":
            try:
                return getattr(self, f"decrypt_{type(encrypted_obj).__name__.lower()}")(encrypted_obj)
            except Exception as exc:
                raise DecryptionError(exc)
        return encrypted_obj


    def encrypt_str(self, string: str) -> str:
        """
        Encrypts a string using the encryption key.

        :param string: string to be encrypted
        :return: encrypted string and signature
        """
        if not isinstance(string, str):
            raise TypeError("string must be a string")
        r = TextCrypt(self.key).encrypt(string)
        return r


    def decrypt_str(self, cipher_string: str) -> Encryptable:
        """
        Decrypts an encrypted string using the encryption key.

        :param cipher_string: encrypted string to be decrypted
        :param signature: signature of the encrypted string
        :return: decrypted object
        """
        if not isinstance(cipher_string, str):
            raise TypeError("cipher_string must be a string")

        text_crypt = TextCrypt(self.key)
        type_ = None
        split = cipher_string.split('\u0000')
        if cipher_string.startswith(':ty-') and len(split) > 1:
            if len(split) == 2:
                type_, cipher_str = split
                r = text_crypt.decrypt(cipher_str)
            else:
                type_ = split[0]
                rem_cipher_str = "\u0000".join(split[1:])
                r = self.decrypt(rem_cipher_str)
        else:
            r = text_crypt.decrypt(cipher_string)

        if not type_:
            return str(r)
        if type_ == ":ty-ndbl:":
            return int(r)
        elif type_ == ":ty-dbl:":
            return float(r)
        elif type_ == ":ty-bln:":
            return eval(r)
        elif type_ == ":ty-b:":
            return base64.urlsafe_b64decode(r.encode())
        elif type_ == ":ty-obj:":
            return pickle.loads(r)


    def encrypt_int(self, int_: int) -> str:
        """
        Encrypts an integer

        :param int_: integer to be encrypted
        :return: encrypted integer as a string
        """
        if not isinstance(int_, int):
            raise TypeError(int_)
        enc_int = self.encrypt_str(str(int_))
        return f":ty-ndbl:\u0000{enc_int}"


    def encrypt_float(self, float_: float) -> str:
        """
        Encrypts a float

        :param float_: float to be encrypted
        :return: encrypted float as a string
        """
        if not isinstance(float_, float):
            raise TypeError(float_)
        enc_float = self.encrypt_str(str(float_))
        return f":ty-dbl:\u0000{enc_float}"


    def encrypt_bool(self, bool_: bool) -> str:
        """
        Encrypts a boolean

        :param bool_: boolean to be encrypted
        :return: encrypted boolean as a string
        """
        if not isinstance(bool_, bool):
            raise TypeError(bool_)
        enc_bool = self.encrypt_str(str(bool_))
        return f":ty-bln:\u0000{enc_bool}"


    def encrypt_bytes(self, bytes_: bytes) -> str:
        """
        Encrypts a bytes content

        :param bytes_: bytes containing contents to be encrypted
        :return: string of encrypted bytes content
        """
        if not isinstance(bytes_, bytes):
            raise TypeError(bytes_)
        bytes_str = base64.urlsafe_b64encode(bytes_).decode()
        enc_bytes_str = self.encrypt_str(bytes_str)
        return f":ty-b:\u0000{enc_bytes_str}"


    def encrypt_tuple(self, tuple_: Tuple) -> Tuple:
        """
        Encrypts a tuple content

        :param tuple_: tuple containing contents to be encrypted
        :return: tuple with contents encrypted
        """
        if not isinstance(tuple_, tuple):
            raise TypeError(tuple_)
        return tuple(self.encrypt_list(list(tuple_)))
    

    def decrypt_tuple(self, cipher_tuple: Tuple) -> Tuple:
        """
        Decrypts a tuple of encrypted content

        :param cipher_tuple: tuple of encrypted content to be decrypted
        :return: tuple of decrypted content
        """
        if not isinstance(cipher_tuple, tuple):
            raise TypeError(cipher_tuple)
        return tuple(self.decrypt_list(list(cipher_tuple)))


    def encrypt_set(self, set_: Set) -> Set:
        """
        Encrypts a set content

        :param set_: set containing contents to be encrypted
        :return: set with contents encrypted
        """
        if not isinstance(set_, set):
            raise TypeError(set_)
        return set(self.encrypt_list(list(set_)))
    

    def decrypt_set(self, cipher_set: Set) -> Set:
        """
        Decrypts a set of encrypted content

        :param cipher_set: set of encrypted content to be decrypted
        :return: set of decrypted content
        """
        if not isinstance(cipher_set, set):
            raise TypeError(cipher_set)
        return set(self.decrypt_list(list(cipher_set)))


    def encrypt_list(self, list_: List) -> List:
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

    
    def decrypt_list(self, cipher_list: List) -> List:
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

    
    def encrypt_dict(self, dict_: Dict) -> Dict:
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

    
    def decrypt_dict(self, cipher_dict: Dict) -> Dict:
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
    

    def _encrypt_object(self, object_: object) -> str:
        """
        Encrypts a Python class object

        :param object_: Python class object to be encrypted
        :return: encrypted Python class object
        """
        dumped_obj = pickle.dumps(object_)
        encrypted_obj = self.encrypt_bytes(dumped_obj)
        return f":ty-obj:\u0000{encrypted_obj}"


    
