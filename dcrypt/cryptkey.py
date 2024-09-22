from __future__ import annotations
import inspect
import rsa
from cryptography.fernet import Fernet
from typing import Callable, List, Optional, TypeVar, Generic, Type

from .exceptions import SignatureError
from .signature import Signature, SUPPORTED_HASH_ALGORITHMS, SIGNATURE_STRENGTH_LEVELS
from .exceptions import InvalidCryptKey


T = TypeVar("T")

class _SetOnceDescriptor(Generic[T]):
    """
    Descriptor that allows an attribute to be set only once on an instance.
    """
    def __init__(self, attr_type: Optional[Type[T]] = None, validators: List[Callable[..., None]] = None) -> None:
        """
        Initialize the descriptor

        :param name: name of the attribute
        :param validators: list of validators to be used to validate the attribute's value
        """
        if attr_type and not inspect.isclass(attr_type):
            raise TypeError('attr_type must be a class')
        if validators and not isinstance(validators, list):
            raise TypeError('validators must be a list')
        
        self.attr_type = attr_type or object
        self.validators = validators or []
        for validator in self.validators:
            if not callable(validator):
                raise TypeError('validators must be a list of callables')
        return None
            
    
    def __set_name__(self, owner, name: str) -> None:
        if not isinstance(name, str):
            raise TypeError('name must be a string')
        self.name = name


    def __get__(self, instance: object, owner: object) -> T:
        """
        Get the property value

        :param instance: instance of the class
        :param owner: class that owns the instance
        :return: value of the attribute
        """
        if instance is None:
            return self
        value = instance.__dict__[self.name]
        return value


    def __set__(self, instance: object, value: T) -> None:
        """
        Set the attribute value on the instance

        :param instance: instance of the class
        :param value: value to be set
        """
        if self.name in instance.__dict__:
            raise AttributeError(f'Attribute {self.name} can only be set once')
        if not isinstance(value, self.attr_type):
            raise TypeError(f'{self.name} must be of type {self.attr_type}')
        
        for validator in self.validators:
            validator(value)
        instance.__dict__[self.name] = value

    
    def __delete__(self, instance: object) -> None:
        """
        Delete the attribute value on the instance

        :param instance: instance of the class
        """
        if self.name in instance.__dict__:
            del instance.__dict__[self.name]
        return None



class CryptKey:
    """Encryption key for `*Crypt` classes"""
    signature = _SetOnceDescriptor(Signature)

    def __init__(
        self, 
        signature: Optional[Signature] = None, 
        signature_strength: int = 1,
        hash_algorithm: str = "SHA-256"
    ) -> None:
        """
        Make a `CryptKey` object

        :param signature: key signature. Pass this if you already have a key signature
        and just need to reconstruct the CryptKey object.
        :param signature_strength: key signature strength. Default to 1. 
        :param hash_algorithm: hash algorithm to use. Default to SHA-256.
        
        You can specify the strength of the key signature. There a three levels. The higher the strength, 
        the longer it takes to generate the key signature but the more secure it is.
        This is only used when `signature` is not passed to the constructor, that is, you want to create
        an entirely new crypt key.
        """        
        self.signature = signature or self.make_signature(signature_strength, hash_algorithm)


    def __eq__(self, o: object) -> bool:
        if not isinstance(o, self.__class__):
            return False
        return self.signature == o.signature
    

    @property
    def master(self) -> bytes:
        """
        Returns the master key.

        The master key is the fernet key used to encrypt and decrypt data.
        """
        enc_master, pub_key, priv_key, hash_method = self.signature
        return self._decrypt_master_key(enc_master, priv_key, pub_key, hash_method)

    @property
    def is_valid(self) -> bool:
        """
        Checks if the cryptkey is valid
        """
        try:
            self.master
        except Exception:
            return False
        return True


    @classmethod
    def _sign_master_key(
        cls, 
        master_key: bytes, 
        priv_key: rsa.PrivateKey,
        hash_algorithm: str,
    ) -> bytes:
        """
        Signs the master key using the rsa private key

        :param master_key: fernet key to be signed
        :param priv_key: rsa private key
        :param hash_algorithm: hash algorithm to use to sign the master key
        :return: master key's signature
        """
        return rsa.sign(master_key, priv_key, hash_algorithm)


    @classmethod
    def _verify_master_key(
        cls, 
        master_key: bytes, 
        key_signature: bytes, 
        pub_key: rsa.PublicKey,
        hash_algorithm: str
    ) -> bool:
        """
        Verifies a decrypted master key using the public key

        :param master_key: fernet key to be verified
        :param key_signature: signature of the master key
        :param hash_algorithm: hash algorithm used to sign the master key
        :param pub_key: rsa public key
        """
        try:
            return rsa.verify(master_key, key_signature, pub_key) == hash_algorithm
        except Exception:
            return False


    @classmethod
    def _encrypt_master_key(
        cls, 
        master_key: bytes, 
        pub_key: rsa.PublicKey, 
        priv_key: Optional[rsa.PrivateKey] = None,
        hash_algorithm: Optional[str] = None
    ) -> bytes:
        enc_master_key = rsa.encrypt(master_key, pub_key)
        if priv_key and hash_algorithm:
            key_signature = cls._sign_master_key(master_key, priv_key, hash_algorithm)
            enc_master_key = br'\u0000'.join((enc_master_key, key_signature))
        return enc_master_key


    @classmethod
    def _decrypt_master_key(
        cls, 
        enc_master_key: bytes, 
        priv_key: rsa.PrivateKey, 
        pub_key: Optional[rsa.PublicKey] = None,
        hash_algorithm: Optional[str] = None
    ) -> bytes:
        if hash_algorithm:
            enc_master_key, signature = enc_master_key.split(br'\u0000')

        master_key = rsa.decrypt(enc_master_key, priv_key)
        if hash_algorithm and pub_key:
            is_verified = cls._verify_master_key(master_key, signature, pub_key, hash_algorithm)
            if not is_verified:
                raise SignatureError('Key signature cannot be verified. Might have been tampered with.')
        return master_key
    

    @classmethod
    def make_signature(cls, signature_strength: int = 1, hash_algorithm: str = "SHA-256") -> Signature:
        """
        Generates a new key signature.
        The object generated can be used to make a `CryptKey` object

        :param signature_strength: key signature strength. Default to 1.
        :param hash_algorithm: hash algorithm to use. Default to SHA-256.
        :return: a `Signature` object
        """
        if not isinstance(signature_strength, int):
            raise TypeError('signature_strength must be an integer')
        
        if not 1 <= signature_strength <= len(SIGNATURE_STRENGTH_LEVELS):
            raise ValueError(f'signature_strength must be between 1 and {len(SIGNATURE_STRENGTH_LEVELS)}')

        if hash_algorithm not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f'hash_algorithm must be one of {SUPPORTED_HASH_ALGORITHMS}')
        
        strength_lvl_index = signature_strength - 1
        bits = SIGNATURE_STRENGTH_LEVELS[strength_lvl_index][1]
        pub_key, priv_key = rsa.newkeys(bits)

        master_key = Fernet.generate_key()
        enc_master_key = cls._encrypt_master_key(master_key, pub_key, priv_key, hash_algorithm)
        return Signature(enc_master_key, pub_key, priv_key, hash_algorithm)



def validate_cryptkey(key: CryptKey) -> None:
    """
    Checks if a key is valid

    :param key: key to be checked
    :raises `InvalidCryptKey`: if the key is invalid
    """
    if not isinstance(key, CryptKey):
        raise TypeError('key must be of type CryptKey')
    if not key.is_valid:
        raise InvalidCryptKey(
            'Crypt key provided is not valid. Its signature may have been tampered with.'
        )
    return None
