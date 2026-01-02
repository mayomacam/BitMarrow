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
