<<<<<<< HEAD
# 🔐 CryptoPass

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey)
![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-green)
![Version](https://img.shields.io/badge/release-v4.0.0-red)

**CryptoPass** is an advanced, local-first password manager and cryptographic suite designed for high-security environments. Distinct from cloud-based alternatives, it operates entirely offline with a zero-knowledge architecture, ensuring your secrets are decrypted **only in volatile memory** and never touch your disk.

---

## 🛡️ Critical Security Features (v4.0.0)

### 🧠 RAM-Only Architecture
Unlike standard password managers that may leave temporary files, CryptoPass v4.0 uses **SQLite Deserialization** to decrypt your vault directly from the encrypted container into RAM.
- **No Temporary Files**: Unencrypted data never touches the filesystem (not even in `%TEMP%`).
- **Aggressive Cleanup**: Triggered garbage collection (`gc.collect`) on vault lock/exit.

### 🔐 Defense-in-Depth
- **Full-File Encryption**: The entire database (`vault.db`) is an AES-256-GCM encrypted container.
- **Argon2id Hashing**: State-of-the-art memory-hard key derivation to resist GPU brute-force attacks.
- **Hardware Binding**: Optional session persistence is cryptographically bound to your specific device hardware ID.
- **Strict Session Policy**: "Stay Logged In" sessions are **PIN-gated** and expire automatically after **24 hours** (configurable).

---

## ✨ Capabilities

### 🔑 Credential Vault
- **Organized Storage**: Bank-grade encryption for passwords, usernames, URLs, and notes.
- **Smart Generation**: Generate high-entropy passwords (up to 128 chars) with custom rules.
- **Strength Meter**: Real-time analysis of password complexity and reuse risks.
- **Visual Privacy**: Global "Eye" toggles used by default for all sensitive fields.

### 📝 Secure Note-Taker
- **Encrypted Docs**: Write sensitive notes in Markdown with live preview.
- **Blob Storage**: Securely attach files and images (`blobs.db`) directly into your encrypted notes.
- **Auto-Save**: Changes are encrypted and committed instantly.

### 📜 Cryptographic Lab
- **Key Generation**: Create expert-grade keys without external tools:
  - **RSA** (2048/4096-bit)
  - **Ed25519**
  - **SSH Keys** (OpenSSH format)
  - **Certificates** (X.509 Self-Signed)
- **Key Vault**: dedicated secure storage for your private keys and certificates.

### ⚡ Modern Experience
- **Premium UI**: Built with `CustomTkinter` for a seamless dark-mode experience.
- **Quick Unlock**: Use a 4-8 digit PIN for rapid access on trusted devices.
- **Portability**: Fully self-contained "Portable Mode" support via custom data paths.
- **Backup System**: Create encrypted `.cpback` archives for safe off-site storage.

---

## 🚀 Installation & Setup

### Prerequisites
- Python **3.10** or higher (Required for `sqlite3.deserialize`).

### Manual Install
1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/cryptopass.git
   cd cryptopass
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/Mac
   source .venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch Application**
   ```bash
   python main.py
   ```

---

## 📖 Usage Guide

### First Run
1. **Master Password**: You will be prompted to set a strong Master Password. This is the **only** way to recover your vault.
2. **Recovery Mnemonic**: A 24-word BIP-39 phrase will be generated. **Write this down.** It bypasses all other security layers if you lose your password.
3. **Security Setup**: You will be asked to configure:
   - **Everyday Password**: A separate password for daily login (wraps the Master Key).
   - **Quick PIN**: A fast unlock code for this specific device.

### Migration
Moving to a new PC?
1. Go to **Settings > Migration**.
2. Generate a **Transfer Key**.
3. Copy the `vault.db` (and `blobs.db`) to the new machine.
4. On the new machine, launch CryptoPass. It will detect the hardware mismatch and ask for the Transfer Key.

---

## 🏗️ Building Executable
To create a standalone `.exe` for Windows:

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile --icon=assets/icon.ico --name "CryptoPass" main.py
```
*(No separate installation required for end-users)*

---

## 📄 License
**CryptoPass** is Free Software licensed under the **GNU General Public License v3.0 (GPLv3)**.

You are free to use, modify, and distribute this software, but **all derivative works must remain open-source**. This ensures the tool remains auditable and trustworthy for the community.

See [LICENSE](./LICENSE) for full text.

---

## ⚠️ Disclaimer
*This software is provided "as is", without warranty of any kind. While it adheres to modern security standards/practices, the authors are not liable for any data loss. Always maintain external backups of your Recovery Phrase.*
=======
# 🔐 CryptoPass v1.2.0

**CryptoPass** is a high-security, local-first password manager and cryptographic key generator. Built with Python and CustomTkinter, it features a modern GUI, industrial-grade encryption (AES-256-GCM), and a comprehensive vault for both passwords and X.509 certificates.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Security](https://img.shields.io/badge/security-AES--256--GCM-green.svg)
![Version](https://img.shields.io/badge/version-1.2.0-orange.svg)

---

## ✨ Features

### 🛡️ Core Security
- **Strict Enforced Policy**: Mandatory 12+ character passwords with complexity rules (Upper/Lower/Digit/Special).
- **Security Checklist**: Real-time visual validation during setup to prevent weak secrets.
- **AES-256-GCM**: Authenticated encryption for all sensitive vault fields.
- **Argon2id**: Memory-hard, state-of-the-art master password hashing.

### 📜 Certificate & Key Vault
- **Certificate Management:** Import, parse, and store X.509 certificates (`.pem`, `.crt`).
- **Metadata Extraction:** Automatically extracts Common Name, Issuer, and Expiry dates.
- **Multi-Algorithm Key Gen:** 
  - **Asymmetric:** RSA (up to 4096-bit), Ed25519, X.509.
  - **Symmetric:** AES-256, ChaCha20, HMAC.
  - **SSH:** OpenSSH format Ed25519 and RSA keys.

### 📲 Smart Login & Recovery
- **Multi-Factor Auth (MFA):** Integrated TOTP authenticator support.
- **Tiered Access:** 
  - **Master Password:** Root authority for setup and recovery.
  - **Login Password + TOTP:** Fast, secure daily access.
- **BIP-39 Recovery:** 24-word "Seed Phrase" for ultimate disaster recovery.

### 📊 User Experience
- **Modern Dark UI:** Sleek, responsive design built with CustomTkinter.
- **Vault Analytics:** Visual stats on password age and strength distribution.
- **Session Auto-Lock:** Configurable timeout (5m to 24h) with thread-safe management.
- **Secure Clipboard:** Auto-clears sensitive data after 30 seconds.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- [Git](https://git-scm.com/)

### Quick Start

1. **Clone & Enter:**
   ```bash
   git clone https://github.com/yourusername/cryptopass.git
   cd cryptopass
   ```

2. **Install Requirements:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run:**
   ```bash
   python main.py
   ```

---

## 🛠️ Building Standalone

Create a portable executable for your OS:

```bash
pip install pyinstaller
# Windows
pyinstaller --noconsole --onefile --add-data "gui;gui" --name "CryptoPass" main.py
```
*See [BUILDING.md](./BUILDING.md) for full cross-platform instructions.*

---

## 🔒 Security Architecture

### Key Hierarchy
CryptoPass uses a tiered unsealing mechanism for the **Data Encryption Key (DEK)**:
- **Master Path:** Master Password → Argon2id → MKEK → Unseals DEK.
- **Daily Path:** Login Password + TOTP Key → Unseals DEK (Session-restricted).

### Zero-Knowledge Policy
We never store your passwords or keys. All data is encrypted locally using keys derived on-the-fly. If you lose your Master Password and Recovery Mnemonic, your data is unrecoverable even by us.

---

## 🗺️ Roadmap (Milestone 2)
- [ ] **SQLCipher Integration:** Transition to full-database-level encryption.
- [ ] **Auto-Lock Triggers:** Lock on system sleep/lid close.
- [ ] **Audit Logging:** Encrypted history of vault modifications.
- [ ] **E2E Cloud Sync:** Secure, client-side encrypted synchronization.

---

## 📄 License
Licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer
CryptoPass is provided "as is". While it implements top-tier security standards, we recommend keeping your 24-word recovery phrase in a physical, safe location.
>>>>>>> 6b91baecfa0930c653d444e61194cb7690e1fceb
