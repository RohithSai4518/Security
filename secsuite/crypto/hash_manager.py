"""
Multi-algorithm Hash Calculator, HMAC Generator, and Checksum Verifier.
"""

import hashlib
import hmac
import os
from typing import Dict, Optional, List
from secsuite.core.logger import logger

SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b"]

class HashManager:
    """Computes, checks, and generates cryptographic hashes and HMAC signatures."""

    @staticmethod
    def hash_text(data: str, algorithm: str = "sha256") -> str:
        algo = algorithm.lower()
        if algo not in hashlib.algorithms_available:
            raise ValueError(f"Algorithm '{algorithm}' is not supported on this platform.")
        h = hashlib.new(algo)
        h.update(data.encode("utf-8"))
        return h.hexdigest()

    @staticmethod
    def hash_file(filepath: str, algorithm: str = "sha256", chunk_size: int = 65536) -> str:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        algo = algorithm.lower()
        h = hashlib.new(algo)
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def multi_hash_text(data: str, algorithms: Optional[List[str]] = None) -> Dict[str, str]:
        algos = algorithms or ["md5", "sha1", "sha256", "sha512"]
        results = {}
        for algo in algos:
            try:
                results[algo] = HashManager.hash_text(data, algo)
            except ValueError:
                pass
        return results

    @staticmethod
    def multi_hash_file(filepath: str, algorithms: Optional[List[str]] = None) -> Dict[str, str]:
        algos = algorithms or ["md5", "sha1", "sha256", "sha512"]
        results = {}
        for algo in algos:
            try:
                results[algo] = HashManager.hash_file(filepath, algo)
            except (ValueError, FileNotFoundError):
                pass
        return results

    @staticmethod
    def generate_hmac(key: bytes, message: bytes, algorithm: str = "sha256") -> str:
        algo = algorithm.lower()
        return hmac.new(key, message, getattr(hashlib, algo, hashlib.sha256)).hexdigest()

    @staticmethod
    def verify_hmac(key: bytes, message: bytes, expected_hmac: str, algorithm: str = "sha256") -> bool:
        computed = HashManager.generate_hmac(key, message, algorithm)
        # Constant-time comparison to protect against timing attacks
        return hmac.compare_digest(computed.lower(), expected_hmac.lower())

    @staticmethod
    def verify_checksum(filepath: str, expected_hash: str, algorithm: str = "sha256") -> bool:
        actual = HashManager.hash_file(filepath, algorithm)
        matches = hmac.compare_digest(actual.lower(), expected_hash.lower())
        if matches:
            logger.success(f"Checksum verification passed for {os.path.basename(filepath)} ({algorithm})")
        else:
            logger.error(f"Checksum mismatch for {os.path.basename(filepath)}! Expected: {expected_hash}, Actual: {actual}")
        return matches
