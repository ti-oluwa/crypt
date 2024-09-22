"""
#### dcrypt

Encrypt and decrypt data using RSA and Fernet encryption.

@Author: Daniel T. Afolayan (ti-oluwa.github.io)
"""

from .signature import Signature, CommonSignature
from .cryptkey import CryptKey
from .text import TextCrypt
from .object import ObjectCrypt
from .json import JSONCrypt
from .exceptions import EncryptionError, DecryptionError


__version__ = '0.0.6'
__all__ = [
    'Signature', 'CommonSignature', 
    'CryptKey', 'TextCrypt', 'ObjectCrypt', 
    'JSONCrypt', 'EncryptionError', 'DecryptionError'
]
__author__ = "Daniel T. Afolayan"
