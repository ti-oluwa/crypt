import unittest
import os

from dcrypt.signature import CommonSignature
from dcrypt.cryptkey import CryptKey


class TestCommonSignature(unittest.TestCase):

    def setUp(self):
        self.signature = CryptKey.make_signature().common()
        self.file_dir = os.path.abspath('./tests/fixtures')

    def test_common_signature(self):
        self.assertIsInstance(self.signature, CommonSignature)
        self.assertTrue(len(self.signature) == 4)
        with self.assertRaises(AttributeError):
            self.signature.hash_method = "md5"

    def test_json(self):
        self.assertIsInstance(self.signature.json(), dict)
        self.assertTrue(len(self.signature.json()) == 4)

    def test_dump_and_load(self):
        self.signature.dump(f"{self.file_dir}/commonsignature.json")
        self.assertTrue(os.path.exists(f"{self.file_dir}/commonsignature.json"))
        self.assertEqual(self.signature, CommonSignature.load(f"{self.file_dir}/commonsignature.json"))

    def tearDown(self):
        if os.path.exists(f"{self.file_dir}/commonsignature.json"):

            os.remove(f"{self.file_dir}/commonsignature.json")


if __name__ == "__main__":
    unittest.main()
