
class InvalidCryptKey(Exception):
    pass


class SignatureError(Exception):
    pass


class EncryptionError(Exception):
    """Error encrypting object."""


class DecryptionError(Exception):
    """Error decrypting object."""

