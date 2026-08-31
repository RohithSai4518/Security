"""
Unit tests for Cryptography and Key Generation modules.
"""

import unittest
import os
import tempfile
from secsuite.crypto.hash_manager import HashManager
from secsuite.crypto.symmetric import SymmetricCipher
from secsuite.crypto.key_gen import KeyGenerator

class TestCryptoModule(unittest.TestCase):

    def test_hash_text_sha256(self):
        text = "PySecSuite-Security-Test"
        expected = "e030eb516e93368d13d21a7a69840e4aeb6b76c69a58a95e390a0b8d703f99b5"
        actual = HashManager.hash_text(text, "sha256")
        self.assertEqual(actual, expected)

    def test_multi_hash_text(self):
        text = "integrity-test"
        hashes = HashManager.multi_hash_text(text, ["sha1", "sha256", "sha512"])
        self.assertIn("sha1", hashes)
        self.assertIn("sha256", hashes)
        self.assertIn("sha512", hashes)
        self.assertEqual(len(hashes["sha256"]), 64)

    def test_file_hash_and_verification(self):
        with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as f:
            f.write("Secret Payload for File Hashing")
            temp_path = f.name

        try:
            sha256_val = HashManager.hash_file(temp_path, "sha256")
            self.assertTrue(HashManager.verify_checksum(temp_path, sha256_val, "sha256"))
            self.assertFalse(HashManager.verify_checksum(temp_path, "0" * 64, "sha256"))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_hmac_generation_and_verification(self):
        key = b"super-secret-key-123"
        msg = b"transaction-payload"
        sig = HashManager.generate_hmac(key, msg, "sha256")
        self.assertTrue(HashManager.verify_hmac(key, msg, sig, "sha256"))
        self.assertFalse(HashManager.verify_hmac(key, msg, "tampered" + sig[8:], "sha256"))

    def test_symmetric_encryption_roundtrip(self):
        plaintext = "Confidential Information & Sensitive Parameters"
        passphrase = "CorrectHorseBatteryStaple#2026!"
        
        token = SymmetricCipher.encrypt(plaintext, passphrase)
        self.assertIsInstance(token, str)
        self.assertNotEqual(token, plaintext)

        decrypted = SymmetricCipher.decrypt(token, passphrase)
        self.assertEqual(decrypted, plaintext)

    def test_symmetric_decryption_wrong_password(self):
        plaintext = "Critical Security String"
        token = SymmetricCipher.encrypt(plaintext, "PasswordA")
        with self.assertRaises(ValueError):
            SymmetricCipher.decrypt(token, "PasswordB")

    def test_password_generation_and_entropy(self):
        pwd = KeyGenerator.generate_complex_password(length=24)
        self.assertEqual(len(pwd), 24)
        entropy = KeyGenerator.calculate_entropy(pwd)
        self.assertGreater(entropy["entropy_bits"], 70)
        self.assertEqual(entropy["strength"], "Very Strong")

    def test_token_and_api_key_gen(self):
        token = KeyGenerator.generate_random_token(16)
        self.assertEqual(len(token), 32)
        api_key = KeyGenerator.generate_api_key(prefix="test", length=30)
        self.assertTrue(api_key.startswith("test_"))

if __name__ == "__main__":
    unittest.main()
