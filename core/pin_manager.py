"""
PIN management for quick vault access.
Uses Argon2id for PIN hashing and AES-256-GCM for wrapping the master key.
"""
import os
import hashlib
from typing import Optional, Tuple
from core.encryption import EncryptionManager
from core.key_derivation import KeyDerivation
from core.secure_memory import zero_memory

class PinManager:
    """Manages PIN-based authentication and key wrapping."""
    
    def __init__(self, key_derivation: KeyDerivation, hardware_id: str):
        self.kdf = key_derivation
        self.hardware_id = hardware_id

    def _derive_pin_key(self, pin: str, salt: bytes) -> bytearray:
        """
        Derives a key from PIN + HardwareID + Salt.
        HardwareID ensures the PIN is only valid on this device.
        """
        # Combine PIN and HardwareID for more entropy
        secret = f"{pin}:{self.hardware_id}"
        return self.kdf.derive_key(secret, salt)

    def setup_pin(self, pin: str, master_key: bytearray) -> Tuple[str, bytes, bytes]:
        """
        Sets up a new PIN.
        Returns (pin_hash, salt, wrapped_key).
        """
        salt = self.kdf.generate_salt()
        pin_hash = self.kdf.hash_password(pin) # We hash the PIN normally for verification
        
        pin_key = self._derive_pin_key(pin, salt)
        temp_enc = EncryptionManager(pin_key)
        
        wrapped_key = temp_enc.encrypt_bytes(bytes(master_key))
        
        zero_memory(pin_key)
        return pin_hash, salt, wrapped_key

    def verify_and_unwrap(self, pin: str, stored_hash: str, 
                          salt: bytes, wrapped_key: bytes) -> Optional[bytearray]:
        """
        Verifies the PIN and unwraps the master key.
        """
        if not self.kdf.verify_password(pin, stored_hash):
            return None
            
        try:
            pin_key = self._derive_pin_key(pin, salt)
            temp_enc = EncryptionManager(pin_key)
            
            master_key_bytes = temp_enc.decrypt_bytes(wrapped_key)
            zero_memory(pin_key)
            
            return bytearray(master_key_bytes)
        except Exception:
            return None
