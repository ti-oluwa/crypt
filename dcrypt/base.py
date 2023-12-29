from cryptography.fernet import Fernet

from .exceptions import InvalidCryptKey
from .cryptkey import CryptKey, _AllowSetOnce


def validate_cryptkey(key: CryptKey) -> None:
    """
    Checks if a key is valid

    :param key: key to be checked
    :raises InvalidCryptKey: if the key is invalid
    """
    if not isinstance(key, CryptKey):
        raise TypeError('key must be of type CryptKey')
    if not key.is_valid:
        raise InvalidCryptKey('Crypt key provided is not valid. Its signature may have been tampered with.')



class TCrypt:
    """
    Encrypts and decrypts text using Fernet + RSA Encryption
    """
    key = _AllowSetOnce(name='key', attr_type=CryptKey, validators=[validate_cryptkey])

    def __init__(self, key: CryptKey) -> None:
        """
        Initializes the Crypt object

        :param key: encryption key.
        """
        self.key = key


    def __eq__(self, o: object) -> bool:
        if not isinstance(o, self.__class__):
            return False
        return self.key == o.key


    def encrypt(self, string: str, encoding: str = 'utf-8') -> str:
        """
        Encrypts a string using the fernet key

        :param string: string to be encrypted
        :param encoding: encoding to be used to decode and 
        encode the string on encryption. Default to 'utf-8'
        :return: encrypted string
        """
        if not isinstance(string, str):
            raise TypeError('string must be of type str')

        string_bytes = string.encode(encoding=encoding)
        cipher_bytes = Fernet(self.key.master).encrypt(string_bytes)
        cipher_string = cipher_bytes.decode(encoding=encoding)
        return cipher_string


    def decrypt(self, cipher_string: str, encoding: str = 'utf-8') -> str:
        """
        Decrypts a string using the fernet key

        :param cipher_string: string to be decrypted
        :param encoding: encoding to be used to decode and 
        encode the string on decryption. Default to 'utf-8'
        :return: decrypted string
        """
        if not isinstance(cipher_string, str):
            raise TypeError('cipher_string must be of type str')

        cipher_bytes = cipher_string.encode(encoding=encoding)
        string_bytes = Fernet(self.key.master).decrypt(cipher_bytes)
        string = string_bytes.decode(encoding=encoding)
        return string

