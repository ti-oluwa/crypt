from cryptography.fernet import Fernet

from .base import Crypt
from .exceptions import EncryptionError, DecryptionError


class TextCrypt(Crypt):
    """
    Encrypts and decrypts text.
    """
    def encrypt(self, string: str, encoding: str = 'utf-8') -> str:
        """
        Encrypts a string using cryptkey

        :param string: string to be encrypted
        :param encoding: encoding to be used to decode and 
        encode the string on encryption. Defaults to 'utf-8'
        :return: encrypted string
        """
        if not isinstance(string, str):
            raise TypeError('string must be of type str')

        string_bytes = string.encode(encoding=encoding)
        try:
            cipher_bytes = Fernet(self.key.master).encrypt(string_bytes)
        except Exception as exc:
            raise EncryptionError(exc) from None
        cipher_string = cipher_bytes.decode(encoding=encoding)
        return cipher_string


    def decrypt(self, cipher_string: str, encoding: str = 'utf-8') -> str:
        """
        Decrypts a string using the fernet key

        :param cipher_string: string to be decrypted
        :param encoding: encoding to be used to decode and 
        encode the string on decryption. Defaults to 'utf-8'
        :return: decrypted string
        """
        if not isinstance(cipher_string, str):
            raise TypeError('cipher_string must be of type str')

        cipher_bytes = cipher_string.encode(encoding=encoding)
        try:
            string_bytes = Fernet(self.key.master).decrypt(cipher_bytes)
        except Exception as exc:
            raise DecryptionError(exc) from None
        string = string_bytes.decode(encoding=encoding)
        return string

