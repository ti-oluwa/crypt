from abc import ABC, abstractmethod
from typing import TypeVar

from .cryptkey import CryptKey, _SetOnceDescriptor, validate_cryptkey


Encryptable = TypeVar("Encryptable", str, int, float, bool, bytes, list, tuple, set, dict, None)
Decryptable = TypeVar("Decryptable", str, list, tuple, set, dict, None)

class Crypt(ABC):
    """Abstract base class for `*Crypt` type"""
    key = _SetOnceDescriptor(CryptKey, validators=[validate_cryptkey])

    def __init__(self, key: CryptKey) -> None:
        """
        Initializes the `*Crypt` object

        :param key: encryption key.
        """
        self.key = key


    def __eq__(self, o: object) -> bool:
        if not isinstance(o, self.__class__):
            return False
        return self.key == o.key

    
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(key={self.key})'
        

    @abstractmethod
    def encrypt(self, obj: Encryptable, *args, **kwargs) -> Decryptable:
        """Encrypts the object passed"""
        pass


    @abstractmethod
    def decrypt(self, encrypted_obj: Decryptable, *args, **kwargs) -> Encryptable:
        """Decrypts the encrypted object passed"""
        pass
