# Security Audit Report for BitMarrow

**Date:** 2026-01-07
**Auditor:** Antigravity (AI Agent)
**Target:** BitMarrow Application

## Executive Summary
The BitMarrow application employs strong cryptographic primitives (AES-256-GCM, Argon2id) and a robust "Defense in Depth" strategy with both full-database and field-level encryption. However, a critical vulnerability was identified where the database is decrypted to a temporary file on the disk during runtime, posing a significant data leakage risk.

## Findings

### 1. [CRITICAL] Decrypted Database Stored on Disk
**Location:** `core/database/db_manager.py` methods `_open_sealed_db` and `close`
**Description:** 
When opening an encrypted vault, the application decrypts the entire SQLite database file and writes it to a temporary file (`tempfile.NamedTemporaryFile`) on the disk. This temporary file contains the full, unencrypted vault data.
**Risk:** 
- **Crash/Power Failure:** If the application terminates unexpectedly (crash, force kill, power loss), the `close()` method is not called, and the unencrypted temporary file remains in the system's `%TEMP%` directory.
- **Forensics:** Deleted files on HDDs/SSDs can often be recovered.
- **Access Control:** Malicious processes running as the same user can watch the `%TEMP%` directory and copy the file while the app is running.
**Remediation:** 
Use SQLite's in-memory deserialization. Decrypt the database into a memory buffer and use `sqlite3.connect(":memory:")` followed by `deserialize()` to mount the database without ever touching the disk.

### 2. [HIGH] Insecure Memory Handling (String Objects)
**Location:** GUI Input Fields (`ctk.CTkEntry`) throughout `gui/`
**Description:** 
Python's `tkinter` (and by extension `customtkinter`) wrappers handle text input as immutable Python `str` objects. These strings cannot be manually zeroed out (overwritten) in memory.
**Risk:** 
A memory dump of the running process could reveal passwords entered into the login or entry fields.
**Remediation:** 
This is an inherent limitation of Python/Tkinter. Use `gc.collect()` aggressively after closing sensitive dialogs to encourage the garbage collector to free these objects, though this does not guarantee immediate overwrite.

### 3. [MEDIUM] "Stay Logged In" Default Security
**Location:** `core/session_manager.py`
**Description:** 
The "Stay Logged In" feature, when used without a PIN, encrypts the master key using a hardware-derived key.
**Risk:** 
Any malware running in the user's session can access the OS Keyring, retrieve the token, and decrypt the vault without user interaction.
**Remediation:** 
Enforce or strongly recommend setting a PIN when "Stay Logged In" is enabled to act as a second factor (What you have + What you know).

### 4. [POSITIVE] Cryptographic Hygiene
**Description:**
- **Algorithm:** AES-256-GCM is correctly used with unique nonces.
- **KDF:** Argon2id is used with appropriate parameters.
- **Entropy:** `os.urandom` is used for salts and nonces.
- **Integrity:** `check_integrity` ensures the DB is bound to the device.

## Action Plan
1. Refactor `DatabaseManager` to use in-memory databases via `deserialize`. [COMPLETED - v4.0.0]
2. Ensure `gc.collect()` is called after Vault Lock / App Close. [COMPLETED - v4.0.0]
3. Review PIN requirement for session persistence. [POLICY UPDATED: 24h Expiry + PIN Gating enforced - v4.0.0]
