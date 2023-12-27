
class KeyVerificationError(Exception):
    """Fernet key is not verified. Might have been tampered with."""


class EncryptionError(Exception):
    """Error encrypting object."""


class DecryptionError(Exception):
    """Error decrypting object."""

