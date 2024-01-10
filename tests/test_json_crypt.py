import unittest

from dcrypt.json import JSONCrypt
from dcrypt.cryptkey import CryptKey



class TestJSONCrypt(unittest.TestCase):

    def setUp(self):
        self.crypt = JSONCrypt(key=CryptKey())

    def test_crypt(self):
        self.assertIsInstance(self.crypt.key, CryptKey)
        with self.assertRaises(AttributeError):
            self.crypt.key = None

    def test_encrypt_decrypt(self):
        cipher = self.crypt.encrypt((1, 2, 3))
        self.assertIsInstance(cipher, list)
        self.assertNotEqual(cipher, (1, 2, 3))
        for e in cipher:
            self.assertIsInstance(e, str)
            self.assertTrue(len(e) > 0)
        self.assertNotEqual(self.crypt.decrypt(cipher), (1, 2, 3))
        self.assertEqual(self.crypt.decrypt(cipher), [1, 2, 3])

        cipher = self.crypt.encrypt({"a", "b", "c"})
        self.assertIsInstance(cipher, list)
        self.assertNotEqual(cipher, {"a", "b", "c"})
        for v in cipher:
            self.assertIsInstance(v, str)
            self.assertTrue(len(v) > 0)
        self.assertNotEqual(self.crypt.decrypt(cipher), {"a", "b", "c"})


if __name__ == "__main__":
    unittest.main()
