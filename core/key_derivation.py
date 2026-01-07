"""
Key derivation module using Argon2id.
Handles secure salt generation and key derivation for encryption.
"""
import argon2
from core.secure_memory import zero_memory

class KeyDerivation:
    """Manages password hashing and key derivation using Argon2id."""
    
    def __init__(self, 
                 memory_cost: int = 65536, 
                 time_cost: int = 3, 
                 parallelism: int = 4):
        """
        Initializes with Argon2id parameters.
        Default parameters are high for security (64MB RAM, 3 iterations, 4 threads).
        """
        self.hasher = argon2.PasswordHasher(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            type=argon2.Type.ID
        )
    
    def hash_password(self, password: str) -> str:
        """Hashes the master password for verification."""
        return self.hasher.hash(password)
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verifies if a password matches the stored hash."""
        try:
            return self.hasher.verify(hashed, password)
        except argon2.exceptions.VerifyMismatchError:
            return False

    def derive_key(self, password: str, salt: bytes, length: int = 32) -> bytearray:
        """
        Derives an encryption key from the master password and a salt.
        Returns a bytearray that should be zeroed after used to init EncryptionManager.
        """
        # We use Argon2 fixed-length output for key derivation
        # instead of a separate PBKDF2 step if desired, or we can use the same 
        # argon2 underpinnings. Here we use the low-level API.
        from argon2 import low_level
        
        derived = low_level.hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=self.hasher.time_cost,
            memory_cost=self.hasher.memory_cost,
            parallelism=self.hasher.parallelism,
            hash_len=length,
            type=low_level.Type.ID
        )
        return bytearray(derived)

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """Generates a secure random salt."""
        import os
        return os.urandom(length)
    @staticmethod
    def generate_salt_hex(length: int = 16) -> str:
        """Generates a secure random salt in hex format."""
        import os
        return os.urandom(length).hex()