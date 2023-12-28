import rsa
import base64
from cryptography.fernet import Fernet
from typing import NamedTuple

from .exceptions import SignatureError


SIGNATURE_STRENGTH_LEVELS = [
    (1, 1024),
    (2, 2048),
    (3, 4096)
]

SUPPORTED_HASH_ALGORITHMS = ('SHA-256', 'SHA-384', 'SHA-512')


class CommonSignature(NamedTuple):
    """
    `NamedTuple` containing an encrypted Fernet key, the rsa public key 
    and rsa private key used to encrypt the Fernet key, all as strings.
    """
    enc_f_key: str
    pub_key: str
    priv_key: str


class Signature(NamedTuple):
    """
    `NamedTuple` containing an encrypted Fernet key, the rsa public key and 
    rsa private key used to encrypt the Fernet key.
    """
    enc_f_key: bytes
    pub_key: rsa.PublicKey
    priv_key: rsa.PrivateKey

    @staticmethod
    def _rsa_key_to_str(rsa_key: rsa.PublicKey | rsa.PrivateKey, encoding: str = 'utf-8'):
        rsa_key_str = base64.urlsafe_b64encode(rsa_key.save_pkcs1(format="PEM")).decode(encoding=encoding)
        return rsa_key_str


    @staticmethod
    def _rsa_key_from_str(
            rsa_key_str: str, 
            type_: str = "public", 
            encoding: str = 'utf-8'
        ):
        key_bytes = base64.urlsafe_b64decode(rsa_key_str.encode(encoding=encoding))
        if type_ == 'private':
            return rsa.PrivateKey.load_pkcs1(key_bytes, format="PEM")
        elif type_ == 'public':
            return rsa.PublicKey.load_pkcs1(key_bytes, format="PEM")
        raise ValueError('type_ must be either "private" or "public"')


    @staticmethod
    def _enc_f_key_to_str(enc_f_key_bytes: bytes, encoding: str = 'utf-8'):
        return base64.urlsafe_b64encode(enc_f_key_bytes).decode(encoding=encoding)


    @staticmethod
    def _enc_f_key_from_str(enc_f_key_str: str, encoding: str = 'utf-8'):
        return base64.urlsafe_b64decode(enc_f_key_str.encode(encoding=encoding))


    def to_common(self, encoding: str = "utf-8"):
        """
        Converts the signature to a common signature.

        :param encoding: encoding to be used when converting values to strings
        :return: `CommonSignature` object
        """
        enc_f_key_str = self._enc_f_key_to_str(self.enc_f_key, encoding=encoding)
        pub_key_str = self._rsa_key_to_str(self.pub_key, encoding=encoding)
        priv_key_str = self._rsa_key_to_str(self.priv_key, encoding=encoding)
        return CommonSignature(enc_f_key_str, pub_key_str, priv_key_str)
    

    @classmethod
    def from_common(cls, common_signature: CommonSignature, encoding: str = "utf-8"):
        """
        Construct a signature from its common signature

        :param common_signature: `CommonSignature` object
        :param encoding: encoding used to encode the key strings
        :return: created `Signature` object
        """
        enc_f_key = cls._enc_f_key_from_str(common_signature.enc_f_key, encoding=encoding)
        pub_key = cls._rsa_key_from_str(common_signature.pub_key, 'public', encoding=encoding)
        priv_key = cls._rsa_key_from_str(common_signature.priv_key, 'private', encoding=encoding)
        return cls(enc_f_key, pub_key, priv_key)



class CryptKey:
    """Encryption key for `*Crypt` classes"""
    hash_algorithm = 'SHA-256' # Can be any of 'SHA-256', 'SHA-384', 'SHA-512'
    sign_and_verify = True
    __slots__ = ("_signature",)

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
        self._signature = signature or self.make_signature(signature_strength=signature_strength)


    def __eq__(self, o: object):
        if not isinstance(o, self.__class__):
            return False
        return self.signature == o.signature

    @property
    def signature(self) -> Signature:
        """
        Cryptkey's signature. 
        Contains an encrypted fernet key, 
        an rsa public key and an rsa private key
        """
        return self._signature

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
    def _sign_f_key(cls, fernet_key: bytes, rsa_priv_key: rsa.PrivateKey):
        """
        Signs the fernet key using the rsa private key

        :param fernet_key: fernet key to be signed
        :param rsa_priv_key: rsa private key
        :return: signature
        """
        if not cls.hash_algorithm in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f'hash_algorithm must be one of {SUPPORTED_HASH_ALGORITHMS}')
        return rsa.sign(fernet_key, rsa_priv_key, cls.hash_algorithm)


    @classmethod
    def _verify_f_key(
            cls, 
            fernet_key: bytes, 
            signature: bytes, 
            rsa_pub_key: rsa.PublicKey
        ) -> bool:
        """
        Verifies a decrypted fernet key using the public key

        :param fernet_key: fernet key to be verified
        :param signature: signature to be verified
        :param rsa_pub_key: rsa public key
        """
        if not cls.hash_algorithm in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f'hash_algorithm must be one of {SUPPORTED_HASH_ALGORITHMS}')
        return rsa.verify(fernet_key, signature, rsa_pub_key) == cls.hash_algorithm


    @classmethod
    def _encrypt_f_key(
            cls, 
            f_key: bytes, 
            rsa_pub_key: rsa.PublicKey, 
            rsa_priv_key: rsa.PrivateKey = None
        ):
        enc_f_key = rsa.encrypt(f_key, rsa_pub_key)
        if cls.sign_and_verify and rsa_priv_key:
            signature = cls._sign_f_key(f_key, rsa_priv_key)
            enc_f_key = br'\u0000'.join([enc_f_key, signature])
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
