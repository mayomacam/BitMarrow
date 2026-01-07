"""
Encrypted backup manager for vault migration.
"""
import zipfile
import os
import shutil
from pathlib import Path
from typing import Optional

from core.encryption import EncryptionManager

class BackupManager:
    """Handles creation and restoration of encrypted vault backups."""
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def create_backup(self, output_path: Path, encryption_manager: EncryptionManager):
        """
        Creates a zip of the data directory and encrypts it.
        The encryption_manager should be initialized with a key derived from the Migration Transfer Key.
        """
        temp_zip = output_path.with_suffix(".tmp.zip")
        
        try:
            # 1. Zip the required files
            with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_name in ["vault.db", "blobs.db"]:
                    file_path = self.data_dir / file_name
                    if file_path.exists():
                        zf.write(file_path, arcname=file_name)
            
            # 2. Encrypt the zip content
            zip_data = temp_zip.read_bytes()
            encrypted_data = encryption_manager.encrypt_bytes(zip_data)
            
            # 3. Write to final output
            output_path.write_bytes(encrypted_data)
            
            return True
        finally:
            if temp_zip.exists():
                temp_zip.unlink()

    def restore_backup(self, backup_path: Path, target_dir: Path, encryption_manager: EncryptionManager):
        """Decrypts and extracts a backup."""
        temp_zip = target_dir / "restore.tmp.zip"
        
        try:
            # 1. Decrypt
            encrypted_data = backup_path.read_bytes()
            decrypted_data = encryption_manager.decrypt_bytes(encrypted_data)
            
            temp_zip.write_bytes(decrypted_data)
            
            # 2. Extract
            with zipfile.ZipFile(temp_zip, 'r') as zf:
                zf.extractall(target_dir)
            
            return True
        finally:
            if temp_zip.exists():
                temp_zip.unlink()
