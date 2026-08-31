"""
Cryptographically Secure Token, Salt, Password, and Key Generator.
"""

import secrets
import string
import math
from typing import Dict

class KeyGenerator:
    """Generates high-entropy secrets and calculates password entropy."""

    @staticmethod
    def generate_random_token(nbytes: int = 32) -> str:
        """Generates a cryptographically secure URL-safe hex token."""
        return secrets.token_hex(nbytes)

    @staticmethod
    def generate_api_key(prefix: str = "sec", length: int = 40) -> str:
        """Generates an API key with structured prefix."""
        alphabet = string.ascii_letters + string.digits
        key_body = "".join(secrets.choice(alphabet) for _ in range(length))
        return f"{prefix}_{key_body}"

    @staticmethod
    def generate_complex_password(
        length: int = 16,
        include_upper: bool = True,
        include_lower: bool = True,
        include_digits: bool = True,
        include_special: bool = True
    ) -> str:
        """Generates a high-entropy password guaranteed to contain selected character classes."""
        pools = []
        guaranteed = []

        if include_lower:
            pools.append(string.ascii_lowercase)
            guaranteed.append(secrets.choice(string.ascii_lowercase))
        if include_upper:
            pools.append(string.ascii_uppercase)
            guaranteed.append(secrets.choice(string.ascii_uppercase))
        if include_digits:
            pools.append(string.digits)
            guaranteed.append(secrets.choice(string.digits))
        if include_special:
            special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            pools.append(special_chars)
            guaranteed.append(secrets.choice(special_chars))

        if not pools:
            raise ValueError("At least one character pool must be enabled.")

        all_chars = "".join(pools)
        remaining_len = max(0, length - len(guaranteed))
        random_chars = [secrets.choice(all_chars) for _ in range(remaining_len)]

        # Combine and shuffle
        combined = guaranteed + random_chars
        # Secure Fisher-Yates shuffle
        for i in range(len(combined) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            combined[i], combined[j] = combined[j], combined[i]

        return "".join(combined)

    @staticmethod
    def calculate_entropy(password: str) -> Dict[str, float]:
        """Calculates information entropy (bits) for a given password."""
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digits = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digits:
            pool_size += 10
        if has_special:
            pool_size += 32

        if pool_size == 0 or len(password) == 0:
            return {"pool_size": 0, "entropy_bits": 0.0, "strength": "Very Weak"}

        entropy = len(password) * math.log2(pool_size)

        if entropy < 36:
            strength = "Very Weak"
        elif entropy < 60:
            strength = "Moderate"
        elif entropy < 80:
            strength = "Strong"
        else:
            strength = "Very Strong"

        return {
            "length": len(password),
            "pool_size": pool_size,
            "entropy_bits": round(entropy, 2),
            "strength": strength
        }
