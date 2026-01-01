import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from config import DATA_DIR, DB_FILE
from core.encryption import EncryptionManager


class DatabaseManager:
    """Manages encrypted SQLite database operations."""
    
    def __init__(self, encryption_manager: Optional[EncryptionManager] = None):
        self._encryption = encryption_manager
        self._conn: Optional[sqlite3.Connection] = None
        self._db_key: Optional[str] = None
        self._ensure_data_dir()
    
    def _ensure_data_dir(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    def connect(self):
        """Establish database connection."""
        self._conn = sqlite3.connect(str(DB_FILE))
        self._conn.row_factory = sqlite3.Row
        self._init_tables()
    
    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
    
    def set_encryption(self, encryption_manager: EncryptionManager):
        self._encryption = encryption_manager
    
    def _init_tables(self):
        cursor = self._conn.cursor()
        
        # Master configuration with recovery fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_config (
                id INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret BLOB,           -- Encrypted
                backup_key BLOB,            -- Master key encrypted with TOTP
                mnemonic_hash TEXT,         -- Hash of the 24 words
                login_warning TEXT,         -- Persistent warning message
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Standard password entries
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title BLOB NOT NULL,
                username BLOB,
                password BLOB NOT NULL,
                url BLOB,
                notes BLOB,
                category TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Crypto keys
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crypto_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name BLOB NOT NULL,
                key_type TEXT NOT NULL,
                public_key BLOB,
                private_key BLOB,
                key_size INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes BLOB
            )
        ''')
        
        self._conn.commit()

    # ============== Master Config Operations ==============
    
    def has_master_password(self) -> bool:
        cursor = self._conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM master_config')
        count = cursor.fetchone()[0]
        return count > 0
    
    def save_master_config(self, salt: bytes, password_hash: str):
        cursor = self._conn.cursor()
        cursor.execute(
            'INSERT INTO master_config (salt, password_hash) VALUES (?, ?)',
            (salt, password_hash)
        )
        self._conn.commit()

    def get_master_config(self) -> Optional[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT * FROM master_config LIMIT 1')
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def update_recovery_info(self, totp_secret: Optional[bytes] = None, 
                             backup_key: Optional[bytes] = None,
                             mnemonic_hash: Optional[str] = None):
        cursor = self._conn.cursor()
        if totp_secret:
            cursor.execute('UPDATE master_config SET totp_secret = ?', (totp_secret,))
        if backup_key:
            cursor.execute('UPDATE master_config SET backup_key = ?', (backup_key,))
        if mnemonic_hash:
            cursor.execute('UPDATE master_config SET mnemonic_hash = ?', (mnemonic_hash,))
        self._conn.commit()

    def set_login_warning(self, message: Optional[str]):
        cursor = self._conn.cursor()
        cursor.execute('UPDATE master_config SET login_warning = ?', (message,))
        self._conn.commit()

    # ============== Encryption Wrappers ==============

    def _encrypt(self, value: str) -> Optional[bytes]:
        if self._encryption and value is not None:
            return self._encryption.encrypt(value)
        return None

    def _decrypt(self, value: Optional[bytes]) -> Optional[str]:
        if self._encryption and value:
            return self._encryption.decrypt(value)
        return None

    # ============== Password Operations ==============
    
    def add_password(self, title: str, username: str, password: str,
                     url: str = "", notes: str = "", category: str = "") -> int:
        cursor = self._conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (title, username, password, url, notes, category)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            self._encrypt(title),
            self._encrypt(username),
            self._encrypt(password),
            self._encrypt(url),
            self._encrypt(notes),
            category
        ))
        self._conn.commit()
        return cursor.lastrowid
    
    def get_all_passwords(self) -> List[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT * FROM passwords ORDER BY id DESC')
        rows = cursor.fetchall()
        result = []
        for row in rows:
            try:
                result.append({
                    'id': row['id'],
                    'title': self._decrypt(row['title']),
                    'username': self._decrypt(row['username']),
                    'password': self._decrypt(row['password']),
                    'url': self._decrypt(row['url']),
                    'notes': self._decrypt(row['notes']),
                    'category': row['category'],
                    'created_at': row['created_at']
                })
            except Exception:
                continue # Skip if decryption fails
        return result

    # (Other operations like delete, search... simplified for brevity, similar to original)
    def delete_password(self, entry_id: int):
        self._conn.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
        self._conn.commit()

    # ============== Crypto Key Operations ==============

    def add_crypto_key(self, name: str, key_type: str, public_key: str = "",
                       private_key: str = "", key_size: int = 0, notes: str = "") -> int:
        cursor = self._conn.cursor()
        cursor.execute('''
            INSERT INTO crypto_keys (name, key_type, public_key, private_key, key_size, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            self._encrypt(name),
            key_type,
            self._encrypt(public_key),
            self._encrypt(private_key),
            key_size,
            self._encrypt(notes)
        ))
        self._conn.commit()
        return cursor.lastrowid

    def get_all_crypto_keys(self) -> List[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT * FROM crypto_keys')
        rows = cursor.fetchall()
        result = []
        for row in rows:
            try:
                result.append({
                    'id': row['id'],
                    'name': self._decrypt(row['name']),
                    'key_type': row['key_type'],
                    'public_key': self._decrypt(row['public_key']),
                    'private_key': self._decrypt(row['private_key']),
                    'key_size': row['key_size']
                })
            except Exception:
                continue
        return result

    def get_password_stats(self) -> Dict[str, Any]:
        passwords = self.get_all_passwords()
        total = len(passwords)
        categories = {}
        weak_count = 0
        for p in passwords:
            cat = p['category'] or 'Uncategorized'
            categories[cat] = categories.get(cat, 0) + 1
            if len(p['password'] or '') < 12:
                weak_count += 1
        return {
            'total': total,
            'categories': categories,
            'weak_count': weak_count,
            'key_count': len(self.get_all_crypto_keys())
        }
