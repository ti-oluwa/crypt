import unittest
import os

from dcrypt.signature import Signature, CommonSignature
from dcrypt.cryptkey import CryptKey


class TestSignature(unittest.TestCase):

    def setUp(self):
        self.signature = CryptKey.make_signature()
        self.file_dir = os.path.abspath('./tests/fixtures')

    def test_signature(self):
        self.assertIsInstance(self.signature, Signature)
        self.assertTrue(len(self.signature) == 4)
        with self.assertRaises(AttributeError):
            self.signature.hash_method = "md5"

    def test_common(self):
        self.assertIsInstance(self.signature.common(), CommonSignature)
        self.assertEqual(self.signature, Signature.from_common(self.signature.common()))

    def test_dump_and_load(self):
        self.signature.dump(f'{self.file_dir}/signature.json')
        self.assertTrue(os.path.exists(f"{self.file_dir}/signature.json"))
        self.assertEqual(self.signature, Signature.load(f'{self.file_dir}/signature.json'))

    def tearDown(self):
        if os.path.exists(f"{self.file_dir}/signature.json"):
            os.remove(f"{self.file_dir}/signature.json")


if __name__ == "__main__":
    unittest.main()
    