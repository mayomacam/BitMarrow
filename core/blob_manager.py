"""
Secure blob storage for files and images using a secondary encrypted database.
"""
import sqlite3
import os
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any

from core.encryption import EncryptionManager

class BlobManager:
    """Manages a secondary encrypted database for large binary objects (blobs)."""
    
    def __init__(self, blob_db_path: Path, encryption_manager: EncryptionManager):
        self.db_path = blob_db_path
        self._encryption = encryption_manager
        self._conn: Optional[sqlite3.Connection] = None
        self._conn: Optional[sqlite3.Connection] = None
        
        self.connect()

    def connect(self):
        """Standard connect logic with corruption handling."""
        import time
        
        should_init_new = not self.db_path.exists()
        
        if not should_init_new:
            try:
                encrypted_data = self.db_path.read_bytes()
                decrypted_data = self._encryption.decrypt_bytes(encrypted_data)
                
                self._conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.deserialize(decrypted_data)
                self._init_tables()
            except Exception as e:
                print(f"BlobDB corruption detected: {e}")
                # Backup corrupt file
                backup_path = self.db_path.with_suffix(f".corrupt.{int(time.time())}")
                try:
                    self.db_path.rename(backup_path)
                    print(f"Backed up corrupted blob DB to {backup_path}")
                except Exception:
                    pass
                should_init_new = True
        
        if should_init_new:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._init_tables()
            self._seal_db()

    def _init_tables(self):
        self._conn.execute('''
            CREATE TABLE IF NOT EXISTS blobs (
                id TEXT PRIMARY KEY,
                name TEXT,
                mime_type TEXT,
                content BLOB,
                size INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self._conn.commit()

    def _seal_db(self):
        """Re-encrypt the memory DB back to disk."""
        if not self._conn: return
        
        try:
            data = self._conn.serialize()
            encrypted_data = self._encryption.encrypt_bytes(data)
            
            # Atomic write
            temp_path = self.db_path.with_suffix(".new")
            temp_path.write_bytes(encrypted_data)
            temp_path.replace(self.db_path)
        except Exception as e:
            print(f"Failed to seal BlobDB: {e}")

    def store_blob(self, name: str, mime_type: str, data: bytes) -> str:
        """Encrypts and stores a blob. Returns blob_id."""
        blob_id = hashlib.sha256(data + os.urandom(8)).hexdigest()[:16]
        
        # We also encrypt the content bytes before storing in DB for double protection
        # though the whole file is encrypted too.
        encrypted_content = self._encryption.encrypt_bytes(data)
        
        self._conn.execute('''
            INSERT INTO blobs (id, name, mime_type, content, size)
            VALUES (?, ?, ?, ?, ?)
        ''', (blob_id, name, mime_type, encrypted_content, len(data)))
        self._conn.commit()
        self._seal_db()
        return blob_id

    def retrieve_blob(self, blob_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves and decrypts a blob."""
        cursor = self._conn.execute('SELECT * FROM blobs WHERE id = ?', (blob_id,))
        row = cursor.fetchone()
        if not row: return None
        
        decrypted_content = self._encryption.decrypt_bytes(row['content'])
        return {
            'id': row['id'],
            'name': row['name'],
            'mime_type': row['mime_type'],
            'content': decrypted_content,
            'size': row['size']
        }

    def delete_blob(self, blob_id: str):
        self._conn.execute('DELETE FROM blobs WHERE id = ?', (blob_id,))
        self._conn.commit()
        self._seal_db()

    def close(self):
        if self._conn:
            self._seal_db()
            self._conn.close()
            self._conn = None
