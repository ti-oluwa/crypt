import unittest

from dcrypt.object import ObjectCrypt
from dcrypt.cryptkey import CryptKey
from dcrypt.exceptions import DecryptionError


class TestObjectCrypt(unittest.TestCase):

    def setUp(self):
        self.crypt = ObjectCrypt(key=CryptKey())

    def test_crypt(self):
        self.assertIsInstance(self.crypt.key, CryptKey)
        with self.assertRaises(AttributeError):
            self.crypt.key = None

    def test_encrypt_decrypt(self):        
        self.assertEqual(self.crypt.encrypt(None), None)
        self.assertEqual(self.crypt.decrypt(None), None)
        self.assertEqual(self.crypt.encrypt(""), "")
        self.assertEqual(self.crypt.decrypt(""), "")

        cipher = self.crypt.encrypt("Hello World")
        self.assertIsInstance(cipher, str)
        self.assertTrue(len(cipher) > 0)
        self.assertNotEqual(cipher, "Hello World")
        self.assertEqual(self.crypt.decrypt(cipher), "Hello World")
        
        cipher = self.crypt.encrypt(123)
        self.assertIsInstance(cipher, str)
        self.assertTrue(len(cipher) > 0)
        self.assertNotEqual(cipher, 123)
        self.assertEqual(self.crypt.decrypt(cipher), 123)

        cipher = self.crypt.encrypt(123.456)
        self.assertIsInstance(cipher, str)
        self.assertTrue(len(cipher) > 0)
        self.assertNotEqual(cipher, 123.456)
        self.assertEqual(self.crypt.decrypt(cipher), 123.456)

        cipher = self.crypt.encrypt(True)
        self.assertIsInstance(cipher, str)
        self.assertTrue(len(cipher) > 0)
        self.assertNotEqual(cipher, True)
        self.assertEqual(self.crypt.decrypt(cipher), True)

        cipher = self.crypt.encrypt(False)
        self.assertIsInstance(cipher, str)
        self.assertTrue(len(cipher) > 0)
        self.assertNotEqual(cipher, False)
        self.assertEqual(self.crypt.decrypt(cipher), False)

        cipher = self.crypt.encrypt([1, 2, 3])
        self.assertIsInstance(cipher, list)
        self.assertNotEqual(cipher, [1, 2, 3])
        for e in cipher:
            self.assertIsInstance(e, str)
            self.assertTrue(len(e) > 0)
        self.assertEqual(self.crypt.decrypt(cipher), [1, 2, 3])

        cipher = self.crypt.encrypt((1, 2, 3))
        self.assertIsInstance(cipher, tuple)
        self.assertNotEqual(cipher, (1, 2, 3))
        for e in cipher:
            self.assertIsInstance(e, str)
            self.assertTrue(len(e) > 0)
        self.assertEqual(self.crypt.decrypt(cipher), (1, 2, 3))

        cipher = self.crypt.encrypt({"a": 1, "b": 2, "c": 3})
        self.assertIsInstance(cipher, dict)
        self.assertNotEqual(cipher, {"a": 1, "b": 2, "c": 3})
        for v in cipher:
            self.assertIsInstance(v, str)
            self.assertTrue(len(v) > 0)
        self.assertEqual(self.crypt.decrypt(cipher), {"a": 1, "b": 2, "c": 3})

        cipher = self.crypt.encrypt({"a", "b", "c"})
        self.assertIsInstance(cipher, set)
        self.assertNotEqual(cipher, {"a", "b", "c"})
        for v in cipher:
            self.assertIsInstance(v, str)
            self.assertTrue(len(v) > 0)
        self.assertEqual(self.crypt.decrypt(cipher), {"a", "b", "c"})

        cipher = self.crypt.encrypt(b"Hello World")
        self.assertIsInstance(cipher, str)
        self.assertTrue(len(cipher) > 0)
        self.assertEqual(self.crypt.decrypt(cipher), b"Hello World")

        new_crypt = ObjectCrypt(key=CryptKey())
        with self.assertRaises(DecryptionError):
            new_crypt.decrypt(cipher)

    def test_decoration(self):
        @self.crypt
        def func(input):
            return input

        self.assertNotEqual(func(123), 123)
        self.assertEqual(self.crypt.decrypt(func(123)), 123)

        with self.assertRaises(TypeError):
            _ = self.crypt(1)


if __name__ == "__main__":
    unittest.main()
