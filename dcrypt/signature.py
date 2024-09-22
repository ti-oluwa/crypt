import rsa
import base64
from typing import NamedTuple, Dict, Any, Union
import rsa.pkcs1
import simple_file_handler as sfh


SIGNATURE_STRENGTH_LEVELS = [
    (1, 1024),
    (2, 2048),
    (3, 3072)
]

SUPPORTED_HASH_ALGORITHMS = list(rsa.pkcs1.HASH_METHODS.keys())


def _bytes_to_str(b: bytes, encoding: str = 'utf-8') -> str:
    """
    Converts given bytes to a string.

    :param b: bytes to be converted
    :param encoding: encoding to be used when converting the bytes to a string
    :return: converted string
    """
    return base64.urlsafe_b64encode(b).decode(encoding=encoding)


def _str_to_bytes(s: str, encoding: str = 'utf-8') -> bytes:
    """
    Converts given string to bytes.

    :param s: string to be converted
    :param encoding: encoding to be used when converting the string to bytes
    :return: converted bytes
    """
    return base64.urlsafe_b64decode(s.encode(encoding=encoding))


def _rsa_key_to_str(rsa_key: Union[rsa.PublicKey, rsa.PrivateKey], encoding: str = 'utf-8') -> str:
    """Converts an rsa key to a string"""
    rsa_key_str = _bytes_to_str(rsa_key.save_pkcs1(format="PEM"), encoding=encoding)
    return rsa_key_str


def _rsa_key_from_str(
        rsa_key_str: str, 
        type_: str = "public", 
        encoding: str = 'utf-8'
    ) -> rsa.PublicKey | rsa.PrivateKey:
    """Converts an rsa key string to an rsa key"""
    key_bytes = _str_to_bytes(rsa_key_str, encoding=encoding)
    if type_ == 'private':
        return rsa.PrivateKey.load_pkcs1(key_bytes, format="PEM")
    elif type_ == 'public':
        return rsa.PublicKey.load_pkcs1(key_bytes, format="PEM")
    raise ValueError('type_ must be either "private" or "public"')



class CommonSignature(NamedTuple):
    """
    `NamedTuple` containing an encrypted Fernet key, the rsa public key 
    and rsa private key used to encrypt the Fernet key, all as strings.
    """
    enc_master_key: str
    pub_key: str
    priv_key: str
    hash_method: str

    def json(self) -> Dict[str, Any]:
        """Converts the signature to a dictionary"""
        return self._asdict()
    

    def dump(self, path: str) -> None:
        """
        Dumps the signature to a JSON file.

        :param path: path to the file
        :raises `ValueError`: if the file is not a JSON file
        :raises `FileExistsError`: if the file already exists
        """
        with sfh.FileHandler(path, exists_ok=False) as hdl:
            if not hdl.filetype == "json":
                raise ValueError("Invalid JSON file path.")
            hdl.write_to_file(self.json())


    @classmethod
    def load(cls, path: str):
        """
        Loads a signature from a JSON file.

        :param path: path to the file
        :return: loaded `CommonSignature` object
        :raises `ValueError`: if the file is not a JSON file
        :raises `FileNotFoundError`: if the file does not exist
        """
        with sfh.FileHandler(path, not_found_ok=False) as hdl:
            if not hdl.filetype == "json":
                raise ValueError("Invalid JSON file path.")
            dump: Dict = hdl.read_file()
            return cls(**dump)
    


class Signature(NamedTuple):
    """
    `NamedTuple` containing an encrypted Fernet key, the rsa public key and 
    rsa private key used to encrypt the Fernet key.
    """
    enc_master_key: bytes
    pub_key: rsa.PublicKey
    priv_key: rsa.PrivateKey
    hash_method: str

    def common(self, encoding: str = "utf-8") -> CommonSignature:
        """
        Converts the signature to a string based `CommonSignature` object.

        :param encoding: encoding to be used when converting byte values to strings
        :return: `CommonSignature` object
        """
        enc_master_key_str = _bytes_to_str(self.enc_master_key, encoding=encoding)
        pub_key_str = _rsa_key_to_str(self.pub_key, encoding=encoding)
        priv_key_str = _rsa_key_to_str(self.priv_key, encoding=encoding)
        return CommonSignature(enc_master_key_str, pub_key_str, priv_key_str, self.hash_method)
    

    @classmethod
    def from_common(cls, common_signature: CommonSignature, encoding: str = "utf-8"):
        """
        Construct a signature from its common signature

        :param common_signature: `CommonSignature` object
        :param encoding: encoding used to encode the key strings
        :return: created `Signature` object
        """
        enc_master_key = _str_to_bytes(common_signature.enc_master_key, encoding=encoding)
        pub_key = _rsa_key_from_str(common_signature.pub_key, 'public', encoding=encoding)
        priv_key = _rsa_key_from_str(common_signature.priv_key, 'private', encoding=encoding)
        return cls(enc_master_key, pub_key, priv_key, common_signature.hash_method)


    def dump(self, path: str, encoding: str = "utf-8") -> None:
        """
        Dumps the signature to a JSON file.

        :param path: path to the file
        :param encoding: encoding to be used when converting byte values to strings
        :raises `ValueError`: if the file is not a JSON file
        :raises `FileExistsError`: if the file already exists
        """
        self.common(encoding=encoding).dump(path)


    @classmethod
    def load(cls, path: str, encoding: str = "utf-8"):
        """
        Loads a signature from a JSON file.

        :param path: path to the file
        :param encoding: encoding used to encode the key strings
        :return: loaded `Signature` object
        :raises `ValueError`: if the file is not a JSON file
        :raises `FileNotFoundError`: if the file does not exist
        """
        return cls.from_common(CommonSignature.load(path), encoding=encoding)
