import unittest

from dcrypt.text import TextCrypt
from dcrypt.cryptkey import CryptKey
from dcrypt.exceptions import DecryptionError


class TestTextCrypt(unittest.TestCase):

    def setUp(self):
        self.crypt = TextCrypt(key=CryptKey())

    def test_crypt(self):
        self.assertIsInstance(self.crypt.key, CryptKey)
        with self.assertRaises(AttributeError):
            self.crypt.key = None

    def test_encrypt_decrypt(self):
        with self.assertRaises(TypeError):
            self.crypt.encrypt(None)
        with self.assertRaises(TypeError):
            self.crypt.encrypt(1)
        with self.assertRaises(TypeError):
            self.crypt.encrypt(1.1)
        with self.assertRaises(TypeError):
            self.crypt.encrypt(True)
        with self.assertRaises(TypeError):
            self.crypt.encrypt(b"")
        with self.assertRaises(TypeError):
            self.crypt.encrypt(bytearray())
        with self.assertRaises(TypeError):
            self.crypt.encrypt([1, 2, 3])
        with self.assertRaises(TypeError):
            self.crypt.encrypt((1, 2, 3))
        with self.assertRaises(TypeError):
            self.crypt.encrypt({"a": 1, "b": 2})
        with self.assertRaises(TypeError):
            self.crypt.encrypt({1, 2, 3})
        with self.assertRaises(TypeError):
            self.crypt.encrypt(object())
        with self.assertRaises(TypeError):
            self.crypt.encrypt(object)
        with self.assertRaises(TypeError):
            self.crypt.encrypt(None)
        
        cipher = self.crypt.encrypt("Hello World")
        self.assertIsInstance(cipher, str)
        self.assertTrue(len(cipher) > 0)
        self.assertNotEqual(cipher, "Hello World")
        decipher = self.crypt.decrypt(cipher)
        self.assertEqual(decipher, "Hello World")

        new_crypt = TextCrypt(key=CryptKey())
        with self.assertRaises(DecryptionError):
            new_crypt.decrypt(cipher)


if __name__ == "__main__":
    unittest.main()
