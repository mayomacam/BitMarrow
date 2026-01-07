"""
Encryption manager using AES-256-GCM for authenticated encryption.
Incorporates secure memory handling to wipe keys after use.
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core.secure_memory import zero_memory

class EncryptionManager:
    """Manages encryption and decryption of data using AES-256-GCM."""
    
    def __init__(self, key: bytearray):
        """
        Initializes with a 256-bit (32-byte) key.
        The key must be a bytearray.
        """
        if not isinstance(key, bytearray) or len(key) != 32:
            raise ValueError("Key must be a 32-byte bytearray")
        
        # We store a copy of the key locally to derive the AESGCM object
        self._key = bytearray(key)
        self._aesgcm = AESGCM(self._key)
    
    def encrypt(self, data: str) -> bytes:
        """
        Encrypts a string and returns a combined nonce + ciphertext + tag blob.
        """
        nonce = os.urandom(12)  # Recommended 12-byte nonce for AES-GCM
        ciphertext = self._aesgcm.encrypt(nonce, data.encode(), None)
        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes) -> str:
        """
        Decrypts bytes and returns the original string.
        Expects combined nonce + ciphertext + tag.
        """
        return self.decrypt_bytes(encrypted_data).decode()

    def encrypt_bytes(self, data: bytes) -> bytes:
        """
        Encrypts raw bytes and returns a combined nonce + ciphertext + tag blob.
        """
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt_bytes(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts bytes and returns the original bytes.
        """
        if len(encrypted_data) < 12:
            raise ValueError("Data too short")
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        return self._aesgcm.decrypt(nonce, ciphertext, None)

    def cleanup(self):
        """Wipes the internal key from memory."""
        zero_memory(self._key)
        # We don't have direct access to the internal state of self._aesgcm,
        # but zeroing our copy is a major step.
    
    @staticmethod
    def generate_random_bytes(length: int = 32) -> bytearray:
        """Generates cryptographically secure random bytes as a bytearray."""
        return bytearray(os.urandom(length))

    @staticmethod
    def generate_random_hex(length: int = 32) -> str:
        """Generates a random hex string."""
        return os.urandom(length).hex()
    @staticmethod
    def generate_random_base64(length: int = 32) -> str:
        """Generates a random base64 string."""
        import base64
        return base64.b64encode(os.urandom(length)).decode()    