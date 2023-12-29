import rsa
import base64
from typing import NamedTuple, Self



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
    def _rsa_key_to_str(rsa_key: rsa.PublicKey | rsa.PrivateKey, encoding: str = 'utf-8') -> str:
        """Converts an rsa key to a string"""
        rsa_key_str = base64.urlsafe_b64encode(rsa_key.save_pkcs1(format="PEM")).decode(encoding=encoding)
        return rsa_key_str


    @staticmethod
    def _rsa_key_from_str(
            rsa_key_str: str, 
            type_: str = "public", 
            encoding: str = 'utf-8'
        ) -> rsa.PublicKey | rsa.PrivateKey:
        """Converts an rsa key string to an rsa key"""
        key_bytes = base64.urlsafe_b64decode(rsa_key_str.encode(encoding=encoding))
        if type_ == 'private':
            return rsa.PrivateKey.load_pkcs1(key_bytes, format="PEM")
        elif type_ == 'public':
            return rsa.PublicKey.load_pkcs1(key_bytes, format="PEM")
        raise ValueError('type_ must be either "private" or "public"')


    @staticmethod
    def _enc_f_key_to_str(enc_f_key_bytes: bytes, encoding: str = 'utf-8') -> str:
        """Converts an encrypted fernet key to a string"""
        return base64.urlsafe_b64encode(enc_f_key_bytes).decode(encoding=encoding)


    @staticmethod
    def _enc_f_key_from_str(enc_f_key_str: str, encoding: str = 'utf-8') -> bytes:
        """Converts an encrypted fernet key string to an encrypted fernet key"""
        return base64.urlsafe_b64decode(enc_f_key_str.encode(encoding=encoding))


    def to_common(self, encoding: str = "utf-8") -> CommonSignature:
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
    def from_common(cls, common_signature: CommonSignature, encoding: str = "utf-8") -> Self:
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

