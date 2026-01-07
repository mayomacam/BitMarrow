"""
Audit logging utility for tracking security-sensitive operations.
"""
import logging
from datetime import datetime
from pathlib import Path
from config import DATA_DIR

class AuditLogger:
    """Manages audit logs for security transparency."""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self._ensure_audit_table()

    def _ensure_audit_table(self):
        """Ensures the audit_logs table exists in the database."""
        # This will be called by DatabaseManager
        pass

    def log_event(self, event_type: str, details: str, status: str = "SUCCESS"):
        """Logs an event to the database audit_logs table."""
        try:
            cursor = self.db._conn.cursor()
            cursor.execute('''
                INSERT INTO audit_logs (event_type, details, status, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (event_type, details, status, datetime.now().isoformat()))
            self.db._conn.commit()
        except Exception as e:
            print(f"Failed to log audit event: {e}")

# Event Types
EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILED = "LOGIN_FAILED"
EVENT_PASSWORD_ADD = "PASSWORD_ADD"
EVENT_PASSWORD_EDIT = "PASSWORD_EDIT"
EVENT_PASSWORD_DELETE = "PASSWORD_DELETE"
EVENT_KEY_GEN = "KEY_GEN"
EVENT_DB_MIGRATION = "DB_MIGRATION"
EVENT_SESSION_RESTORED = "SESSION_RESTORED"
