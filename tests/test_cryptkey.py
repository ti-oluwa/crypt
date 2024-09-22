import unittest

from dcrypt.cryptkey import CryptKey
from dcrypt.signature import Signature


class TestCryptKey(unittest.TestCase):

    def setUp(self):
        self.cryptkey = CryptKey()

    def test_cryptkey(self):
        self.assertIsInstance(self.cryptkey.signature, Signature)
        with self.assertRaises(AttributeError):
            self.cryptkey.signature = None
        # with self.assertRaises(TypeError):
            CryptKey(signature="")
        self.assertIsInstance(self.cryptkey.is_valid, bool)
        self.assertIsInstance(self.cryptkey.master, bytes)

    def test_make_signature(self):
        signature = CryptKey.make_signature()
        self.assertIsInstance(signature, Signature)
        self.assertTrue(signature.hash_method, "SHA-256")

        signature = CryptKey.make_signature(hash_algorithm="SHA-512", signature_strength=3)
        self.assertTrue(signature.hash_method, "SHA-512")      
        with self.assertRaises(ValueError):
            CryptKey.make_signature(signature_strength=4)
        with self.assertRaises(ValueError):
            CryptKey.make_signature(hash_algorithm="SHA-6")
        with self.assertRaises(TypeError):
            CryptKey.make_signature(signature_strength="")


if __name__ == "__main__":
    unittest.main()
