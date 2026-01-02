"""
Main application with advanced security: TOTP primary, Password fallback, GCM encryption.
"""
import customtkinter as ctk
import threading
import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from config import APP_NAME, SESSION_TIMEOUT_MINUTES
from core.encryption import EncryptionManager
from core.key_derivation import KeyDerivation
from core.totp_manager import TOTPManager
from core.mnemonic import MnemonicManager
from core.secure_memory import zero_memory, secure_zero
from database.db_manager import DatabaseManager
from gui.login_frame import LoginFrame
from gui.vault_frame import VaultFrame
from gui.password_gen_frame import PasswordGenFrame
from gui.key_gen_frame import KeyGenFrame
from gui.key_vault_frame import KeyVaultFrame
from gui.stats_frame import StatsFrame
from utils.clipboard import ClipboardManager


class CryptoPassApp(ctk.CTk):
    """Main application window with secure recovery flow."""
    
    def __init__(self):
        super().__init__()
        
        self.title(APP_NAME)
        self.geometry("1100x700")
        self.minsize(900, 600)
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Security Modules
        self.db = DatabaseManager()
        self.db.connect()
        self.key_derivation = KeyDerivation()
        self.mnemonic_mgr = MnemonicManager()
        self.totp_mgr = TOTPManager()
        self.encryption: Optional[EncryptionManager] = None
        
        # App State
        self.is_locked = True
        self.session_timer: Optional[threading.Timer] = None
        self.login_warning: Optional[str] = None
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self._show_login()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _show_login(self):
        self.is_locked = True
        for widget in self.winfo_children():
            widget.destroy()
        
        has_setup = self.db.has_master_password()
        self.login_frame = LoginFrame(
            self,
            on_login=self._handle_login,
            on_setup=self._handle_setup,
            is_first_time=not has_setup
        )
        self.login_frame.grid(row=0, column=0, sticky="nsew")

    def _handle_login(self, totp_code: Optional[str] = None, 
                      password: Optional[str] = None) -> bool:
        config = self.db.get_master_config()
        if not config: return False

        if totp_code:
            return self._login_with_totp(totp_code, config)
        elif password:
            return self._login_with_password(password, config)
        return False

    def _login_with_totp(self, code: str, config: dict) -> bool:
        """Unlock using TOTP secret as a key derivation source."""
        encrypted_totp_secret = config.get('totp_secret')
        encrypted_backup_key = config.get('backup_key')
        
        if not encrypted_totp_secret or not encrypted_backup_key:
            return False

        # 1. We need the Master Key to decrypt the TOTP secret. 
        # But wait! If we don't have the Master Key, we can't get the TOTP secret.
        # FIX: The backup_key is encrypted with the TOTP Secret + a secondary salt.
        # But where is the TOTP secret? It's on the user's phone.
        # User enters code -> We still need the SECRET.
        
        # NEW LOGIC: We store a RECOVERY KEY encrypted with the Master Key.
        # We store another copy of the Master Key encrypted with the TOTP SECRET.
        # But the problem is: the app needs the TOTP Secret to verify the code.
        
        # REVISED SECURITY DESIGN FOR "TOTP AS PRIMARY":
        # 1. User sets up Master Password.
        # 2. User sets up TOTP. 
        #    - We store 'totp_secret' UNENCRYPTED (or encrypted with a hardware tag/device ID).
        #    - We store 'master_key_unlocked_by_totp' = Encrypt(MasterKey, key=TOTPSecret).
        # 3. Login:
        #    - User enters code. 
        #    - We verify code against stored 'totp_secret'.
        #    - If OK, we use 'totp_secret' as key to decrypt 'master_key_unlocked_by_totp'.

        # Security check: TOTP secret is base32, usually enough entropy for a key.
        secret_bytes = config.get('totp_secret') # For this flow, let's assume it's stored 
        
        if not secret_bytes: return False
        
        # Verify code
        if not self.totp_mgr.verify_code(secret_bytes.decode(), code):
            return False
            
        # Success! Now decrypt the master key
        try:
            # We derive a key from the secret
            totp_key = bytearray(hashlib.sha256(secret_bytes).digest())
            temp_encryption = EncryptionManager(totp_key)
            
            decrypted_key_raw = temp_encryption.decrypt(encrypted_backup_key)
            zero_memory(totp_key)
            
            # RESILIENCE: Try to detect if it's hex (new format) or legacy string
            try:
                # New format: hex string
                master_key_bytes = bytearray.fromhex(decrypted_key_raw)
            except ValueError:
                # Legacy format: raw bytes as string (latin-1)
                master_key_bytes = bytearray(decrypted_key_raw.encode('latin-1'))
            
            if len(master_key_bytes) != 32:
                raise ValueError(f"Decrypted key length is {len(master_key_bytes)}, expected 32. "
                                 "Database migration required via Master Password.")

            # Initialize main encryption
            self.encryption = EncryptionManager(master_key_bytes)
            self.db.set_encryption(self.encryption)
            
            self._show_main_app()
            return True
        except Exception as e:
            print(f"TOTP Unlock failed: {e}")
            # If we reach here, the database likely has corrupted recovery info from v1.1.0
            # We should guide the user to their Master Password.
            return False

    def _login_with_password(self, password: str, config: dict) -> bool:
        if self.key_derivation.verify_password(password, config['password_hash']):
            key_bytes = self.key_derivation.derive_key(password, config['salt'])
            self.encryption = EncryptionManager(key_bytes)
            self.db.set_encryption(self.encryption)
            zero_memory(key_bytes)
            
            self.login_warning = config.get('login_warning')
            self._show_recovery_choice()
            return True
        return False

    def _show_recovery_choice(self):
        choice_dialog = ctk.CTkToplevel(self)
        choice_dialog.title("Recovery Access")
        choice_dialog.geometry("400x320")
        choice_dialog.transient(self)
        choice_dialog.grab_set()
        
        ctk.CTkLabel(choice_dialog, text="🆘 Recovery Options", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        ctk.CTkLabel(choice_dialog, text="You used recovery. Why?", text_color="gray").pack()
        
        ctk.CTkButton(choice_dialog, text="📱 I lost my phone (Secure Reset)", 
                     command=lambda: self._handle_recovery_action("LOST", choice_dialog),
                     fg_color="#e67e22").pack(pady=10, padx=50, fill="x")
        
        ctk.CTkButton(choice_dialog, text="🕒 Temporary access (Persistent Warning)", 
                     command=lambda: self._handle_recovery_action("TEMP", choice_dialog)).pack(pady=10, padx=50, fill="x")
        
        ctk.CTkButton(choice_dialog, text="Skip for now", 
                     command=lambda: self._handle_recovery_action("SKIP", choice_dialog),
                     fg_color="transparent", text_color="gray").pack()

    def _handle_recovery_action(self, action: str, dialog: ctk.CTkToplevel):
        dialog.destroy()
        if action == "LOST":
            self.db.update_recovery_info(totp_secret=b"", backup_key=b"")
            self._force_password_change()
        elif action == "TEMP":
            msg = "⚠️ Warning: Accessed via recovery. Reset phone access soon."
            self.db.set_login_warning(msg)
            self.login_warning = msg
            self._show_main_app()
        else:
            self._show_main_app()

    def _handle_setup(self, password: str):
        salt = self.key_derivation.generate_salt()
        pass_hash = self.key_derivation.hash_password(password)
        master_key = self.key_derivation.derive_key(password, salt)
        
        self.encryption = EncryptionManager(master_key)
        self.db.save_master_config(salt, pass_hash)
        self.db.set_encryption(self.encryption)
        self.db.set_login_warning(None)
        
        mnemonic = self.mnemonic_mgr.generate_mnemonic()
        self._show_mnemonic_and_setup_totp(mnemonic, master_key)

    def _show_mnemonic_and_setup_totp(self, mnemonic: str, master_key: bytearray):
        """Setup TOTP and show recovery phrase."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Security Setup")
        dialog.geometry("500x600")
        dialog.transient(self)
        dialog.grab_set()
        
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(0, weight=1)
        
        scroll_frame = ctk.CTkScrollableFrame(dialog, fg_color="transparent")
        scroll_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        ctk.CTkLabel(scroll_frame, text="📝 Recovery Phrase", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        ctk.CTkLabel(scroll_frame, text="Write these 24 words down! It is your final fail-safe.", 
                    text_color="#e67e22", wraplength=400).pack(pady=(0, 10))
        
        text = ctk.CTkTextbox(scroll_frame, height=120, width=400)
        text.insert("1.0", mnemonic)
        text.configure(state="disabled")
        text.pack(pady=10)
        
        ctk.CTkLabel(scroll_frame, text="📲 Setup Authenticator (Primary Login)", 
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        secret = self.totp_mgr.generate_secret()
        uri = self.totp_mgr.get_provisioning_uri(secret, "User")
        qr_img = self.totp_mgr.generate_qr_image(uri)
        
        # Convert PIL to TkImage
        from PIL import ImageTk
        img = ctk.CTkImage(light_image=qr_img, dark_image=qr_img, size=(180, 180))
        
        qr_label = ctk.CTkLabel(scroll_frame, image=img, text="")
        qr_label.image = img # Keep reference
        qr_label.pack(pady=5)
        
        ctk.CTkLabel(scroll_frame, text="Enter the 6-digit code to verify:", 
                    font=ctk.CTkFont(size=12)).pack(pady=(10, 5))
        
        verify_entry = ctk.CTkEntry(scroll_frame, width=150, font=ctk.CTkFont(size=16, weight="bold"), justify="center")
        verify_entry.pack(pady=5)
        
        error_label = ctk.CTkLabel(scroll_frame, text="", text_color="#e74c3c")
        error_label.pack()

        def finish():
            code = verify_entry.get().strip().replace(" ", "")
            if not self.totp_mgr.verify_code(secret, code):
                error_label.configure(text="❌ Invalid code. Please try again.")
                return
            
            # Store TOTP info and wrap Master Key
            # Backup Key = MasterKey encrypted with TOTPSecret
            totp_key = bytearray(hashlib.sha256(secret.encode()).digest())
            temp_enc = EncryptionManager(totp_key)
            wrapped_key = temp_enc.encrypt(master_key.hex())
            
            self.db.update_recovery_info(
                totp_secret=secret.encode(),
                backup_key=wrapped_key
            )
            dialog.destroy()
            self._show_main_app()

        ctk.CTkButton(scroll_frame, text="Verify & Finish Setup", command=finish, height=45, font=ctk.CTkFont(weight="bold")).pack(pady=20)

    def _force_password_change(self):
        for widget in self.winfo_children(): widget.destroy()
        self.login_frame = LoginFrame(self, on_login=None, on_setup=self._handle_setup, is_first_time=True)
        self.login_frame.pack(expand=True, fill="both")

    def _show_main_app(self):
        self.is_locked = False
        for widget in self.winfo_children(): widget.destroy()
        self._create_header()
        
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        self.grid_rowconfigure(1, weight=1)
        
        tabs = {
            "🔐 Passwords": VaultFrame, 
            "⚡ Pass Gen": PasswordGenFrame, 
            "🔑 Key Gen": KeyGenFrame, 
            "📜 Key Vault": KeyVaultFrame,
            "📊 Stats": StatsFrame
        }
        self.frames = {}
        for name, frame_cls in tabs.items():
            self.tabview.add(name)
            self.tabview.tab(name).grid_columnconfigure(0, weight=1)
            self.tabview.tab(name).grid_rowconfigure(0, weight=1)
            f = frame_cls(self.tabview.tab(name), self.db)
            f.grid(row=0, column=0, sticky="nsew")
            self.frames[name] = f
            
        self.vault_frame = self.frames["🔐 Passwords"]
        self.vault_frame.refresh()
        self.tabview.configure(command=self._on_tab_change)
        self._reset_session_timer()

    def _create_header(self):
        header = ctk.CTkFrame(self, height=70, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=15, pady=0)
        header.grid_propagate(False)
        
        warn_text = f"   {self.login_warning}" if self.login_warning else ""
        ctk.CTkLabel(header, text=f"🔐 {APP_NAME}{warn_text}", 
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color="#e67e22" if self.login_warning else "white").pack(side="left", pady=10)
        
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right")
        ctk.CTkButton(btn_frame, text="🔒 Lock", width=80, command=self._lock_vault).pack(side="left", padx=5)

    def _lock_vault(self):
        if self.session_timer: self.session_timer.cancel()
        if self.encryption: self.encryption.cleanup()
        self.encryption = None
        self.db.set_encryption(None)
        self._show_login()

    def _on_tab_change(self):
        current = self.tabview.get()
        if "Stats" in current: self.frames["📊 Stats"].refresh()
        elif "Passwords" in current: self.frames["🔐 Passwords"].refresh()
        elif "Key Vault" in current: self.frames["📜 Key Vault"].refresh()

    def _reset_session_timer(self):
        if self.session_timer: self.after_cancel(self.session_timer)
        self.session_timer = self.after(SESSION_TIMEOUT_MINUTES * 60 * 1000, self._lock_vault)

    def _on_close(self):
        if self.encryption: self.encryption.cleanup()
        self.db.close()
        self.destroy()

def main():
    app = CryptoPassApp()
    app.mainloop()

if __name__ == "__main__":
    main()
