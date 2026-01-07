"""
Login and recovery interface for BitMarrow.
Supports TOTP primary login and Master Password emergency fallback.
"""
import customtkinter as ctk
from typing import Callable, Optional
from core.totp_manager import TOTPManager
from gui.components.strength_meter import StrengthMeter
from generators.password_generator import PasswordGenerator
from utils.validators import PasswordValidator

from config import COLOR_BG, COLOR_SURFACE, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM

class LoginFrame(ctk.CTkFrame):
    """Unified login and recovery interface."""
    
    def __init__(self, master, on_login: Callable, on_setup: Callable, 
                 is_first_time: bool = False, has_pin: bool = False, 
                 has_everyday: bool = False, initial_mode: str = "PASSWORD", **kwargs):
        super().__init__(master, fg_color=COLOR_BG, **kwargs)
        
        self.on_login = on_login
        self.on_setup = on_setup
        self.is_first_time = is_first_time
        self.has_pin = has_pin
        self.has_everyday = has_everyday
        self.initial_mode = initial_mode
        
        # Validation checks
        self.check_labels = {}
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_content()
    
    def _create_content(self):
        self.container = ctk.CTkFrame(
            self, width=450, 
            height=650 if self.is_first_time else 500,
            fg_color=COLOR_SURFACE,
            corner_radius=20,
            border_width=1,
            border_color="#333333"
        )
        self.container.grid(row=0, column=0, padx=20, pady=20)
        self.container.grid_propagate(False)
        
        if self.is_first_time:
            self._show_setup_ui()
        elif self.initial_mode == "MIGRATION":
            self._show_migration_challenge_ui()
        elif self.initial_mode == "MNEMONIC":
            self._show_mnemonic_challenge_ui()
        elif self.initial_mode == "PIN_SESSION":
            self._show_pin_session_ui()
        elif self.initial_mode == "EVERYDAY":
            self._show_everyday_login_ui()
        elif self.has_pin and self.initial_mode == "PIN":
            self._show_pin_login_ui()
        else:
            self._show_totp_login_ui()

    def _show_migration_challenge_ui(self):
        """Challenge screen for new devices or vault integrity issues."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="Vault Verification",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color="#e67e22"
        ).pack(pady=(50, 10))
        
        ctk.CTkLabel(
            self.container, text="This database is not bound to this system.\nAuthorize this device to continue.",
            text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=13), justify="center"
        ).pack(pady=(0, 30))
        
        self.mig_key_entry = ctk.CTkEntry(
            self.container, width=300, height=45,
            placeholder_text="Enter Transfer Key",
            fg_color=COLOR_BG, border_color="#e67e22"
        )
        self.mig_key_entry.pack(pady=10)
        
        ctk.CTkButton(
            self.container, text="Verify Transfer Key",
            command=self._handle_mig_key_submit,
            height=45, width=300, fg_color="#e67e22", text_color="white"
        ).pack(pady=10)
        
        ctk.CTkLabel(self.container, text="OR", text_color="gray").pack(pady=10)
        
        self.mnemonic_btn = ctk.CTkButton(
            self.container, text="Use 24-Word Recovery Phrase",
            command=self._show_mnemonic_challenge_ui,
            fg_color="transparent", text_color="#3498db"
        )
        self.mnemonic_btn.pack()
        
        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack(pady=20)

    def _show_mnemonic_challenge_ui(self):
        """Recovery screen for when the transfer key is lost."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="Mnemonic Authorization",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#3498db"
        ).pack(pady=(40, 10))
        
        ctk.CTkLabel(
            self.container, text="Enter your 24-word recovery phrase to claim this vault.\nThis will force-bind the database to this device.",
            text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=12), justify="center"
        ).pack(pady=(0, 20))
        
        self.mnemo_entry = ctk.CTkTextbox(
            self.container, width=350, height=120,
            fg_color=COLOR_BG, border_color="#3498db", border_width=1
        )
        self.mnemo_entry.pack(pady=10)
        
        ctk.CTkButton(
            self.container, text="Authorize This Device",
            command=self._handle_mnemonic_submit,
            height=45, width=300, fg_color="#3498db"
        ).pack(pady=20)
        
        ctk.CTkButton(
            self.container, text="← Back to Key Verification",
            command=self._show_migration_challenge_ui,
            fg_color="transparent", text_color="gray"
        ).pack()

        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack(pady=10)

    def _handle_mig_key_submit(self):
        key = self.mig_key_entry.get().strip()
        if not key: return
        if not self.on_login(migration_key=key):
            self.error_label.configure(text="Invalid or expired Transfer Key")

    def _handle_mnemonic_submit(self):
        phrase = self.mnemo_entry.get("1.0", "end-1c").strip()
        if not phrase: return
        if not self.on_login(mnemonic_phrase=phrase):
            self.error_label.configure(text="Invalid mnemonic phrase")

    def _show_pin_login_ui(self):
        """Standard quick unlock PIN screen."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="Quick Unlock",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=COLOR_TEXT
        ).pack(pady=(60, 10))
        
        ctk.CTkLabel(
            self.container, text="Enter your numeric PIN",
            text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=14)
        ).pack(pady=(0, 40))
        
        self.pin_entry = ctk.CTkEntry(
            self.container, width=200, height=60, 
            font=ctk.CTkFont(size=32, weight="bold"),
            justify="center", placeholder_text="••••••",
            show="•",
            fg_color=COLOR_BG, border_color="#444444",
            corner_radius=12
        )
        self.pin_entry.pack(pady=10)
        self.pin_entry.focus()
        
        self.login_btn = ctk.CTkButton(
            self.container, text="Unlock",
            command=self._handle_pin_login, height=50, width=250,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=COLOR_ACCENT, text_color="black",
            corner_radius=12
        )
        self.login_btn.pack(pady=30)
        
        self.switch_totp_btn = ctk.CTkButton(
            self.container, text="Use Authenticator Code",
            command=self._show_totp_login_ui,
            fg_color="transparent", text_color="#3498db",
            font=ctk.CTkFont(size=12)
        )
        self.switch_totp_btn.pack(pady=5)
        
        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack()

    def _show_pin_session_ui(self):
        """Quick PIN unlock for an existing persistent session."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="Session Locked",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=COLOR_TEXT
        ).pack(pady=(60, 10))
        
        ctk.CTkLabel(
            self.container, text="Enter PIN to restore your session",
            text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=14)
        ).pack(pady=(0, 40))
        
        self.pin_entry = ctk.CTkEntry(
            self.container, width=200, height=60, 
            font=ctk.CTkFont(size=32, weight="bold"),
            justify="center", placeholder_text="••••••",
            show="•",
            fg_color=COLOR_BG, border_color="#444444",
            corner_radius=12
        )
        self.pin_entry.pack(pady=10)
        self.pin_entry.focus()
        
        self.login_btn = ctk.CTkButton(
            self.container, text="Restore Session",
            command=self._handle_pin_session_login, height=50, width=250,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=COLOR_ACCENT, text_color="black",
            hover_color="#27ae60",
            corner_radius=12
        )
        self.login_btn.pack(pady=30)
        
        self.switch_totp_btn = ctk.CTkButton(
            self.container, text="Sign out & Use Password",
            command=self._handle_sign_out_and_switch,
            fg_color="transparent", text_color="#3498db",
            font=ctk.CTkFont(size=12)
        )
        self.switch_totp_btn.pack(pady=5)
        
        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack()

    def _show_everyday_login_ui(self):
        """Daily login using Everyday Password."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="Daily Login",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=COLOR_TEXT
        ).pack(pady=(60, 10))
        
        ctk.CTkLabel(
            self.container, text="Enter your everyday password",
            text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=14)
        ).pack(pady=(0, 40))
        
        self.pass_entry = ctk.CTkEntry(
            self.container, width=300, height=45,
            placeholder_text="Everyday Password",
            show="•",
            fg_color=COLOR_BG, border_color="#444444",
            corner_radius=10
        )
        self.pass_entry.pack(pady=10)
        self.pass_entry.focus()
        
        self.stay_logged_in = ctk.CTkCheckBox(
            self.container, text="Stay Logged In (Binds to device)",
            font=ctk.CTkFont(size=12)
        )
        self.stay_logged_in.pack(pady=10)
        
        self.login_btn = ctk.CTkButton(
            self.container, text="Unlock Vault",
            command=self._handle_everyday_login, height=50, width=250,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=COLOR_ACCENT, text_color="black",
            corner_radius=12
        )
        self.login_btn.pack(pady=30)
        
        self.switch_totp_btn = ctk.CTkButton(
            self.container, text="Use Authenticator Code",
            command=self._show_totp_login_ui,
            fg_color="transparent", text_color="#3498db",
            font=ctk.CTkFont(size=12)
        )
        self.switch_totp_btn.pack(pady=5)
        
        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack()

    def _handle_pin_session_login(self):
        pin = self.pin_entry.get().strip()
        if not pin: return
        if not self.on_login(pin_for_session=pin):
            self.error_label.configure(text="Incorrect PIN")
            self.pin_entry.delete(0, 'end')

    def _handle_everyday_login(self):
        pwd = self.pass_entry.get()
        if not pwd: return
        if not self.on_login(everyday_password=pwd, stay_logged_in=self.stay_logged_in.get()):
            self.error_label.configure(text="Incorrect Everyday Password")

    def _handle_sign_out_and_switch(self):
        # We need help from parent to clear session
        self.master.session_mgr.clear_session()
        self._show_totp_login_ui()

    def _handle_pin_login(self):
        pin = self.pin_entry.get().strip()
        if not pin: return
        
        if not self.on_login(pin=pin):
            self.error_label.configure(text="Invalid PIN")
            self.pin_entry.delete(0, 'end')
    
    def _show_setup_ui(self):
        """First-time Master Password setup with strict enforcement."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="🛡️ Secure Your Vault",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=COLOR_ACCENT
        ).pack(pady=(40, 10))
        
        ctk.CTkLabel(
            self.container, text="Create a strong master password to begin.\nThis is the only way to recover your vault.",
            text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=13),
            justify="center"
        ).pack(pady=(0, 30))
        
        pass_row = ctk.CTkFrame(self.container, fg_color="transparent")
        pass_row.pack(pady=10)
        
        self.pass_entry = ctk.CTkEntry(
            pass_row, show="•", width=300, height=45,
            placeholder_text="Master Password",
            fg_color=COLOR_BG, border_color="#444444"
        )
        self.pass_entry.pack(side="left")
        
        self.pass_visible = False
        self.pass_toggle = ctk.CTkButton(
            pass_row, text="👁", width=45, height=45,
            fg_color=COLOR_BG, border_width=1, border_color="#444444",
            hover_color="#333333",
            command=lambda: self._toggle_visibility("pass")
        )
        self.pass_toggle.pack(side="right", padx=(5, 0))
        
        confirm_row = ctk.CTkFrame(self.container, fg_color="transparent")
        confirm_row.pack(pady=10)
        
        self.confirm_entry = ctk.CTkEntry(
            confirm_row, show="•", width=300, height=45,
            placeholder_text="Confirm Password",
            fg_color=COLOR_BG, border_color="#444444"
        )
        self.confirm_entry.pack(side="left")
        
        self.confirm_visible = False
        self.confirm_toggle = ctk.CTkButton(
            confirm_row, text="👁", width=45, height=45,
            fg_color=COLOR_BG, border_width=1, border_color="#444444",
            hover_color="#333333",
            command=lambda: self._toggle_visibility("confirm")
        )
        self.confirm_toggle.pack(side="right", padx=(5, 0))
        
        self.strength_meter = StrengthMeter(self.container)
        self.strength_meter.pack(pady=15, padx=50, fill="x")
        
        # Security Checklist
        checklist_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        checklist_frame.pack(pady=10, padx=50, fill="x")
        
        self.check_labels = {
            "length": self._create_check_item(checklist_frame, "At least 12 characters"),
            "uppercase": self._create_check_item(checklist_frame, "Uppercase letter"),
            "lowercase": self._create_check_item(checklist_frame, "Lowercase letter"),
            "number": self._create_check_item(checklist_frame, "Number (0-9)"),
            "symbol": self._create_check_item(checklist_frame, "Special character"),
            "strength": self._create_check_item(checklist_frame, "Overall Strength: Good+"),
            "match": self._create_check_item(checklist_frame, "Passwords match")
        }
        
        def _on_input_change(e):
            pwd = self.pass_entry.get()
            confirm = self.confirm_entry.get()
            
            results = PasswordValidator.validate(pwd)
            results['match'] = (pwd == confirm and pwd != "")
            
            # Update Strength Meter
            self.strength_meter.update_strength(results['score'], results['strength_label'])
            
            # Update Checklist
            for key, (label, icon) in self.check_labels.items():
                if results[key]:
                    icon.configure(text="●", text_color=COLOR_ACCENT)
                    label.configure(text_color=COLOR_TEXT)
                else:
                    icon.configure(text="○", text_color=COLOR_TEXT_DIM)
                    label.configure(text_color=COLOR_TEXT_DIM)
            
            # Enable/Disable button
            if results['is_valid'] and results['match']:
                self.setup_btn.configure(state="normal", fg_color=COLOR_ACCENT, text_color="black")
                self.error_label.configure(text="")
            else:
                self.setup_btn.configure(state="disabled", fg_color="#333333")
 
        self.pass_entry.bind("<KeyRelease>", _on_input_change)
        self.confirm_entry.bind("<KeyRelease>", _on_input_change)
        
        self.stay_logged_in = ctk.CTkCheckBox(
            self.container, text="Stay Logged In (Binds to this device)",
            font=ctk.CTkFont(size=12), border_color="#555555"
        )
        self.stay_logged_in.pack(pady=(0, 10))

        self.setup_btn = ctk.CTkButton(
            self.container, text="Create Encrypted Vault",
            command=self._handle_setup, height=50, width=350,
            font=ctk.CTkFont(weight="bold"),
            state="disabled",
            corner_radius=10
        )
        self.setup_btn.pack(pady=20)
        
        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack()
 
    def _create_check_item(self, parent, text):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", pady=2)
        
        icon = ctk.CTkLabel(f, text="○", width=20, text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=14))
        icon.pack(side="left")
        
        label = ctk.CTkLabel(f, text=text, font=ctk.CTkFont(size=12), text_color=COLOR_TEXT_DIM)
        label.pack(side="left", padx=10)
        
        return (label, icon)
 
    def _show_totp_login_ui(self):
        """Standard daily TOTP login."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="Welcome Back",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=COLOR_TEXT
        ).pack(pady=(60, 10))
        
        ctk.CTkLabel(
            self.container, text="Enter your 2FA code to unlock",
            text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=14)
        ).pack(pady=(0, 40))
        
        self.totp_entry = ctk.CTkEntry(
            self.container, width=250, height=60, 
            font=ctk.CTkFont(size=32, weight="bold"),
            justify="center", placeholder_text="000 000",
            fg_color=COLOR_BG, border_color="#444444",
            corner_radius=12
        )
        self.totp_entry.pack(pady=10)
        self.totp_entry.focus()
        
        self.stay_logged_in = ctk.CTkCheckBox(
            self.container, text="Stay Logged In (Binds to this device)",
            font=ctk.CTkFont(size=12), border_color="#555555"
        )
        self.stay_logged_in.pack(pady=(0, 10))

        self.login_btn = ctk.CTkButton(
            self.container, text="Unlock Vault",
            command=self._handle_tot_login, height=50, width=300,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=COLOR_ACCENT, text_color="black",
            hover_color="#27ae60",
            corner_radius=12
        )
        self.login_btn.pack(pady=20)
        
        if self.has_everyday:
            self.switch_everyday_btn = ctk.CTkButton(
                self.container, text="Use Everyday Password Instead",
                command=self._show_everyday_login_ui,
                fg_color="transparent", text_color="#2ecc71",
                font=ctk.CTkFont(size=12)
            )
            self.switch_everyday_btn.pack(pady=2)

        if self.has_pin:
            self.switch_pin_btn = ctk.CTkButton(
                self.container, text="Use PIN Instead",
                command=self._show_pin_login_ui,
                fg_color="transparent", text_color=COLOR_ACCENT,
                font=ctk.CTkFont(size=12)
            )
            self.switch_pin_btn.pack(pady=2)
        
        sep_frame = ctk.CTkFrame(self.container, height=1, fg_color="#333333", width=300)
        sep_frame.pack(pady=10)
        
        self.fallback_btn = ctk.CTkButton(
            self.container, text="Lost Phone? Use Master Password",
            command=self._show_master_login_ui,
            fg_color="transparent", text_color="#3498db",
            hover_color=("#dfe6e9", "#2d3436"),
            font=ctk.CTkFont(size=12)
        )
        self.fallback_btn.pack(pady=10)
 
        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack()
 
    def _show_master_login_ui(self):
        """Emergency Master Password recovery login."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="Vault Recovery",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#e67e22"
        ).pack(pady=(50, 10))
        
        ctk.CTkLabel(
            self.container, text="Verify identity with your master password",
            text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=13)
        ).pack(pady=(0, 30))
        
        pass_row = ctk.CTkFrame(self.container, fg_color="transparent")
        pass_row.pack(pady=10)
        
        self.pass_entry = ctk.CTkEntry(
            pass_row, show="•", width=300, height=45,
            placeholder_text="Master Password",
            fg_color=COLOR_BG, border_color="#444444"
        )
        self.pass_entry.pack(side="left")
        
        self.pass_visible = False
        self.pass_toggle = ctk.CTkButton(
            pass_row, text="👁", width=45, height=45,
            fg_color=COLOR_BG, border_width=1, border_color="#444444",
            hover_color="#333333",
            command=lambda: self._toggle_visibility("pass")
        )
        self.pass_toggle.pack(side="right", padx=(5, 0))
        
        self.stay_logged_in = ctk.CTkCheckBox(
            self.container, text="Stay Logged In (Binds to this device)",
            font=ctk.CTkFont(size=12), border_color="#555555"
        )
        self.stay_logged_in.pack(pady=(0, 10))

        self.recover_btn = ctk.CTkButton(
            self.container, text="Verify Identity",
            command=self._handle_master_recovery, height=50, width=350,
            font=ctk.CTkFont(weight="bold"),
            fg_color="#e67e22", hover_color="#d35400",
            corner_radius=10
        )
        self.recover_btn.pack(pady=20)
        
        self.back_btn = ctk.CTkButton(
            self.container, text="← Back to Secure Login",
            command=self._show_totp_login_ui,
            fg_color="transparent", text_color=COLOR_TEXT_DIM,
            font=ctk.CTkFont(size=12)
        )
        self.back_btn.pack()
 
        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack()
 
    def _toggle_visibility(self, field: str):
        if field == "pass":
            self.pass_visible = not self.pass_visible
            self.pass_entry.configure(show="" if self.pass_visible else "•")
            self.pass_toggle.configure(text="🔒" if self.pass_visible else "👁")
        elif field == "confirm":
            self.confirm_visible = not self.confirm_visible
            self.confirm_entry.configure(show="" if self.confirm_visible else "•")
            self.confirm_toggle.configure(text="🔒" if self.confirm_visible else "👁")

    def _handle_setup(self):
        password = self.pass_entry.get()
        confirm = self.confirm_entry.get()
        
        if password != confirm:
            self.error_label.configure(text="Passwords do not match")
            return
            
        if self.strength_meter.get_score() < 50:
            self.error_label.configure(text="Password is too weak")
            return
            
        self.on_setup(password, self.stay_logged_in.get())
 
    def _handle_tot_login(self):
        code = self.totp_entry.get().strip().replace(" ", "")
        if len(code) != 6:
            self.error_label.configure(text="Please enter 6 digits")
            return
            
        if not self.on_login(totp_code=code, stay_logged_in=self.stay_logged_in.get()):
            self.error_label.configure(text="Invalid code. Try again.")
 
    def _handle_master_recovery(self):
        password = self.pass_entry.get()
        if not password:
            return
            
        if not self.on_login(password=password, stay_logged_in=self.stay_logged_in.get()):
            self.error_label.configure(text="Incorrect master password")
