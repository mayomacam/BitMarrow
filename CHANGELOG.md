# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2026-01-02

### Added
- **Hardened Password Policy**: Enforced mandatory 12-character minimum and strict complexity rules.
- **Security Checklist UI**: Real-time visual validation during password setup/changes.
- **Heuristic Strength Analysis**: Password meter now detects and penalizes common sequences ('123'), repetitions ('aaaa'), and common passcodes.
- **Improved Strength Scaling**: Refined the algorithm to reward complex 16-character passwords with a 100% "Excellent" rating.
- **Scrollable Security Dialogs**: Wrapped setup and verification dialogs in scrollable containers for better accessibility on all screen sizes.
- **Mandatory TOTP Verification**: Mandatory 6-digit code verification during MFA setup to prevent lockout.
- **Migration Resilience**: Added fallback logic to handle legacy encoded TOTP keys and provide clear migration instructions via Master Password.
- **Private Key Privacy**: Implemented "Show/Hide" toggles for all generated and saved private keys to prevent accidental exposure (masked by default).
- **UI Standardisation**: Improved labels to explicitly distinguish between Public Keys/Certificates and Private Secrets.
- **UI Overflow**: Fixed "Verify" button being hidden on smaller screens during setup.
- **Key Generation UI**: Fixed packing order in `KeyGenFrame` where options could be hidden.
- **TOTP Cryptographic Fix**: Fixed "Key must be a 32-byte bytearray" crash by standardizing on hex-encoding for the master key wrapper.

---

## [1.1.0] - 2026-01-01

### Added
- **Certificate Vault**: Full management of X.509 certificates and cryptographic keys.
- **Metadata Parsing**: Support for automatic extraction of Subject, Issuer, and Expiry from certificates.

### Fixed
- **KeyGenFrame Crash**: Resolved `AttributeError` in initialization.
- **SQLite Threading Error**: Fixed `sqlite3.ProgrammingError` using `self.after` timers.
- **UI Render Crashes**: Fixed `TclError` in cross-thread UI operations.

---

## [1.0.0] - 2026-01-01
- Initial release of CryptoPass.
- Core features: Password Vault, Password Generator, GCM Encryption, TOTP & Mnemonic recovery.
