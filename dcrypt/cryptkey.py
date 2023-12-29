import inspect
import rsa
from cryptography.fernet import Fernet
from typing import Callable, List

from .exceptions import SignatureError
from .signature import Signature, SUPPORTED_HASH_ALGORITHMS, SIGNATURE_STRENGTH_LEVELS



class _AllowSetOnce:
    """
    Descriptor that allows an attribute to be set only once on an instance.
    """

    def __init__(self, name: str, attr_type: type[object] = None, validators: List[Callable] = None) -> None:
        """
        Initialize the descriptor

        :param name: name of the attribute
        :param validators: list of validators to be used to validate the attribute's value
        """
        if not isinstance(name, str):
            raise TypeError('name must be a string')
        if attr_type and not inspect.isclass(attr_type):
            raise TypeError('attr_type must be a class')
        if validators and not isinstance(validators, list):
            raise TypeError('validators must be a list')
        
        self.name = name
        self.attr_type = attr_type or object
        self.validators = validators or []
        for validator in self.validators:
            if not callable(validator):
                raise TypeError('validators must be a list of callables')
        return None
            

    def __get__(self, instance: object, owner: object):
        """
        Get the property value

        :param instance: instance of the class
        :param owner: class that owns the instance
        :return: value of the attribute
        """
        if instance is None:
            return self
        value: self.attr_type = instance.__dict__[self.name]
        return value


    def __set__(self, instance: object, value: object) -> None:
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



class CryptKey:
    """Encryption key for `*Crypt` classes"""

    hash_algorithm = 'SHA-256' # Can be any of SUPPORTED_HASH_ALGORITHMS
    sign_and_verify = True # Whether to sign and verify the fernet key
    signature = _AllowSetOnce(name='signature', attr_type=Signature)

    def __init__(
            self, 
            signature: Signature = None, 
            signature_strength: int = 1,
        ):
        """
        Make a `CryptKey` object

        :param signature: key signature. Pass this if you already have a key signature
        and just need to reconstruct the CryptKey object.
        :param signature_strength: key signature strength. Default to 1. 
        
        You can specify the strength of the key signature. There a three levels. The higher the strength, 
        the longer it takes to generate the key signature but the more secure it is.
        This is only used when `signature` is not passed to the constructor, that is, you want to create
        an entirely new crypt key.
        """
        self.signature = signature or self.make_signature(signature_strength=signature_strength)


    def __eq__(self, o: object):
        if not isinstance(o, self.__class__):
            return False
        return self.signature == o.signature
    

    @property
    def master(self) -> bytes:
        """
        Returns the master key.

        The decrypted fernet key
        """
        f, pub, priv = self.signature
        return self._decrypt_f_key(f, priv, pub)

    @property
    def is_valid(self):
        """
        Checks if the cryptkey is valid
        """
        try:
            self.master
        except Exception:
            return False
        return True


    @classmethod
    def _sign_f_key(cls, fernet_key: bytes, rsa_priv_key: rsa.PrivateKey) -> bytes:
        """
        Signs the fernet key using the rsa private key

        :param fernet_key: fernet key to be signed
        :param rsa_priv_key: rsa private key
        :return: ferent key signature
        """
        if not cls.hash_algorithm in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f'hash_algorithm must be one of {SUPPORTED_HASH_ALGORITHMS}')
        return rsa.sign(fernet_key, rsa_priv_key, cls.hash_algorithm)


    @classmethod
    def _verify_f_key(
            cls, 
            fernet_key: bytes, 
            key_signature: bytes, 
            rsa_pub_key: rsa.PublicKey
        ) -> bool:
        """
        Verifies a decrypted fernet key using the public key

        :param fernet_key: fernet key to be verified
        :param key_signature: signature of the fernet key
        :param rsa_pub_key: rsa public key
        """
        if not cls.hash_algorithm in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f'hash_algorithm must be one of {SUPPORTED_HASH_ALGORITHMS}')
        return rsa.verify(fernet_key, key_signature, rsa_pub_key) == cls.hash_algorithm


    @classmethod
    def _encrypt_f_key(
            cls, 
            f_key: bytes, 
            rsa_pub_key: rsa.PublicKey, 
            rsa_priv_key: rsa.PrivateKey = None
        ):
        enc_f_key = rsa.encrypt(f_key, rsa_pub_key)
        if cls.sign_and_verify and rsa_priv_key:
            key_signature = cls._sign_f_key(f_key, rsa_priv_key)
            enc_f_key = br'\u0000'.join([enc_f_key, key_signature])
        return enc_f_key


    @classmethod
    def _decrypt_f_key(
            cls, 
            enc_f_key: bytes, 
            rsa_priv_key: rsa.PrivateKey, 
            rsa_pub_key: rsa.PublicKey = None
        ):
        if cls.sign_and_verify:
            enc_f_key, signature = enc_f_key.split(br'\u0000')
        dec_f_key = rsa.decrypt(enc_f_key, rsa_priv_key)
        if cls.sign_and_verify and rsa_pub_key:
            is_verified = cls._verify_f_key(dec_f_key, signature, rsa_pub_key)
            if not is_verified:
                raise SignatureError('Key signature cannot be verified. Might have been tampered with.')
        return dec_f_key
    

    @classmethod
    def make_signature(cls, signature_strength: int = 1) -> Signature:
        """
        Generates a new key signature.
        The object generated can be used to make a `CryptKey` object

        :returns: a `Signature` object
        """
        if not isinstance(signature_strength, int):
            raise TypeError('signature_strength must be an integer')
        if not 1 <= signature_strength <= 3:
            raise ValueError('signature_strength must be between 1 and 3')
        
        strength_lvl_index = signature_strength - 1
        nbits = SIGNATURE_STRENGTH_LEVELS[strength_lvl_index][1]
        pub_key, priv_key = rsa.newkeys(nbits)

        f_key = Fernet.generate_key()
        enc_f_key = cls._encrypt_f_key(f_key, pub_key, priv_key)
        return Signature(enc_f_key, pub_key, priv_key)
