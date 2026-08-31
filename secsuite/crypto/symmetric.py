"""
Pure Python Authenticated Symmetric Encryption and Decryption Engine.
Uses PBKDF2-HMAC-SHA256 for Key Derivation, HMAC-SHA256 for Authenticity,
and a cryptographically secure stream cipher keystream.
"""

import os
import hashlib
import hmac
import base64
import secrets
from typing import Tuple

from secsuite.core.logger import logger

class SymmetricCipher:
    """
    Authenticated Stream Encryption Engine using PBKDF2-HMAC-SHA256.
    Ensures both Confidentiality and Integrity (AEAD pattern).
    """

    MAGIC_HEADER = b"PYSEC_V1"
    SALT_SIZE = 16
    IV_SIZE = 16
    PBKDF2_ITERATIONS = 100_000

    @classmethod
    def _derive_keys(cls, passphrase: str, salt: bytes) -> Tuple[bytes, bytes]:
        """Derives a 32-byte encryption key and a 32-byte MAC key."""
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            passphrase.encode("utf-8"),
            salt,
            iterations=cls.PBKDF2_ITERATIONS,
            dklen=64
        )
        enc_key = derived[:32]
        mac_key = derived[32:]
        return enc_key, mac_key

    @classmethod
    def _generate_keystream(cls, key: bytes, iv: bytes, length: int) -> bytes:
        """Generates a cryptographic pseudo-random keystream using iterated HMAC-SHA256."""
        blocks = []
        counter = 0
        generated = 0
        while generated < length:
            counter_bytes = counter.to_bytes(4, byteorder="big")
            block = hmac.new(key, iv + counter_bytes, hashlib.sha256).digest()
            blocks.append(block)
            generated += len(block)
            counter += 1
        return b"".join(blocks)[:length]

    @classmethod
    def encrypt(cls, plaintext: str, passphrase: str) -> str:
        """
        Encrypts plaintext with a passphrase.
        Returns Base64 encoded payload: [MAGIC(8) | SALT(16) | IV(16) | HMAC(32) | CIPHERTEXT(N)]
        """
        data = plaintext.encode("utf-8")
        salt = secrets.token_bytes(cls.SALT_SIZE)
        iv = secrets.token_bytes(cls.IV_SIZE)

        enc_key, mac_key = cls._derive_keys(passphrase, salt)
        keystream = cls._generate_keystream(enc_key, iv, len(data))

        # XOR keystream with plaintext
        ciphertext = bytes([b ^ k for b, k in zip(data, keystream)])

        # Compute HMAC over [HEADER + SALT + IV + CIPHERTEXT]
        payload_to_mac = cls.MAGIC_HEADER + salt + iv + ciphertext
        tag = hmac.new(mac_key, payload_to_mac, hashlib.sha256).digest()

        full_payload = cls.MAGIC_HEADER + salt + iv + tag + ciphertext
        return base64.urlsafe_b64encode(full_payload).decode("utf-8")

    @classmethod
    def decrypt(cls, encrypted_token: str, passphrase: str) -> str:
        """Decrypts and authenticates ciphertext token."""
        try:
            raw = base64.urlsafe_b64decode(encrypted_token.encode("utf-8"))
        except Exception:
            raise ValueError("Invalid Base64 token encoding.")

        header_len = len(cls.MAGIC_HEADER)
        if len(raw) < (header_len + cls.SALT_SIZE + cls.IV_SIZE + 32):
            raise ValueError("Token is too short or malformed.")

        header = raw[:header_len]
        if header != cls.MAGIC_HEADER:
            raise ValueError("Invalid payload magic signature.")

        offset = header_len
        salt = raw[offset:offset + cls.SALT_SIZE]
        offset += cls.SALT_SIZE
        iv = raw[offset:offset + cls.IV_SIZE]
        offset += cls.IV_SIZE
        tag = raw[offset:offset + 32]
        offset += 32
        ciphertext = raw[offset:]

        enc_key, mac_key = cls._derive_keys(passphrase, salt)

        # Authenticate payload (Constant-time check)
        payload_to_mac = cls.MAGIC_HEADER + salt + iv + ciphertext
        expected_tag = hmac.new(mac_key, payload_to_mac, hashlib.sha256).digest()

        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication verification failed: Ciphertext has been tampered with or incorrect password.")

        keystream = cls._generate_keystream(enc_key, iv, len(ciphertext))
        decrypted_bytes = bytes([c ^ k for c, k in zip(ciphertext, keystream)])

        return decrypted_bytes.decode("utf-8")
