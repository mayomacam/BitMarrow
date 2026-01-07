"""
Mnemonic recovery module using BIP-39.
Provides a 24-word recovery phrase as an ultimate fail-safe.
"""
from mnemonic import Mnemonic
from core.secure_memory import zero_memory

class MnemonicManager:
    """Manages BIP-39 mnemonic generation and seed derivation."""
    
    def __init__(self, language: str = "english"):
        self.mnemo = Mnemonic(language)
    
    def generate_mnemonic(self) -> str:
        """Generates a 24-word recovery phrase (256 bits of entropy)."""
        return self.mnemo.generate(strength=256)
    
    def is_valid(self, words: str) -> bool:
        """Validates a mnemonic phrase."""
        return self.mnemo.check(words)
    
    def derive_seed(self, words: str, passphrase: str = "") -> bytearray:
        """
        Derives a seed (64 bytes) from a mnemonic and optional passphrase.
        The seed can be used to recreate the master key.
        """
        seed = self.mnemo.to_seed(words, passphrase=passphrase)
        return bytearray(seed)
    
    def mnemonic_to_key(self, words: str, length: int = 32) -> bytearray:
        """
        Derives a specific length encryption key from the mnemonic.
        Uses SHA-512 then truncates/hashes to length.
        """
        import hashlib
        seed = self.derive_seed(words)
        # Use first 32 bytes of the seed as the key or hash it
        key = hashlib.sha256(seed).digest()
        zero_memory(seed)  # Wipe the 64-byte seed
        return bytearray(key[:length])
