# 🔐 CryptoPass

**CryptoPass** is a high-security, local-first password manager and cryptographic key generator. Built with Python and CustomTkinter, it focuses on modern encryption standards (AES-256-GCM), secure memory handling, and a flexible multi-mode recovery system.

![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Security](https://img.shields.io/badge/security-AES--256--GCM-green.svg)

## ✨ Features

### 🛡️ Core Security
- **AES-256-GCM:** Authenticated encryption for all sensitive data.
- **Argon2id:** Industry-leading, memory-hard master password hashing.
- **Secure Memory:** Explicit zeroing of encryption keys in RAM after use.
- **Local First:** Your data never leaves your machine. Encrypted SQLite storage.

### 📲 Smart Login & Recovery
- **TOTP Primary:** 6-digit authenticator code for daily quick access.
- **Master Password Fallback:** 
  - **Lost Phone Mode:** Wipes TOTP and forces a security reset.
  - **Temporary Mode:** Limited access with persistent security warnings.
- **BIP-39 Recovery:** 24-word seed phrase as the ultimate fail-safe.

### 🔑 Generation Tools
- **Password Generator:** 6 types including Standard, Passphrase, PIN, and Pattern-based.
- **Key Generator:** RSA (up to 4096-bit), Ed25519, AES-256, SSH Keys, X.509 Certificates, HMAC, and ChaCha20.
- **Similar Char Randomization:** Increases entropy by randomly swapping look-alike characters (e.g., `0/O`, `1/l`).

### 📊 User Experience
- **Modern Dark UI:** Sleek glassmorphism-inspired design using CustomTkinter.
- **Vault Analytics:** Visual statistics and strength distribution charts.
- **Auto-Lock:** Customizable session timeout for better security.
- **Secure Clipboard:** Auto-clears sensitive data after 30 seconds.

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- [Optional] PyInstaller (for building standalone)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/cryptopass.git
   cd cryptopass
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python main.py
   ```

## 🛠️ Building Standalone

To create a single `.exe` (Windows) or binary (Linux/macOS):

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile --add-data "gui;gui" --name "CryptoPass" main.py
```
*See [BUILDING.md](./BUILDING.md) for detailed instructions.*

## 🔒 Security Architecture

### Key Hierarchy
1. **Master Password** → Argon2id → **Master Key**.
2. **TOTP Secret** → SHA-256 → **TOTP Key**.
3. **Wrapped Key** = Encrypt(Master Key, key=TOTP Key).

### Memory Safety
Unlike standard Python applications, CryptoPass uses `bytearray` buffers for keys and performs manual `zero_memory` operations to mitigate memory scraping attacks.

## 📄 License
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer
While CryptoPass uses industry-standard encryption, use it at your own risk. Always keep your 24-word recovery phrase in a safe, physical location.
