"""
Login and recovery interface for CryptoPass.
Supports TOTP primary login and Master Password emergency fallback.
"""
import customtkinter as ctk
from typing import Callable, Optional
from core.totp_manager import TOTPManager
from gui.components.strength_meter import StrengthMeter

class LoginFrame(ctk.CTkFrame):
    """Unified login and recovery interface."""
    
    def __init__(self, master, on_login: Callable, on_setup: Callable, 
                 is_first_time: bool = False, **kwargs):
        super().__init__(master, **kwargs)
        
        self.on_login = on_login
        self.on_setup = on_setup
        self.is_first_time = is_first_time
        
        self.configure(fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_content()
    
    def _create_content(self):
        self.container = ctk.CTkFrame(self, width=400, height=500)
        self.container.grid(row=0, column=0, padx=20, pady=20)
        self.container.grid_propagate(False)
        
        if self.is_first_time:
            self._show_setup_ui()
        else:
            self._show_totp_login_ui()
    
    def _show_setup_ui(self):
        """First-time Master Password setup."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="🛡️ Initial Setup",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(30, 10))
        
        ctk.CTkLabel(
            self.container, text="Create your recovery master password.\n(Required for initial setup)",
            text_color="gray", font=ctk.CTkFont(size=12)
        ).pack(pady=(0, 20))
        
        self.pass_entry = ctk.CTkEntry(self.container, show="•", width=300, placeholder_text="Master Password")
        self.pass_entry.pack(pady=10)
        
        self.confirm_entry = ctk.CTkEntry(self.container, show="•", width=300, placeholder_text="Confirm Password")
        self.confirm_entry.pack(pady=10)
        
        self.strength_meter = StrengthMeter(self.container)
        self.strength_meter.pack(pady=15, padx=50, fill="x")
        self.pass_entry.bind("<KeyRelease>", lambda e: self.strength_meter.update_strength(self.pass_entry.get()))
        
        self.setup_btn = ctk.CTkButton(
            self.container, text="Create Vault",
            command=self._handle_setup, height=40
        )
        self.setup_btn.pack(pady=20)
        
        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack()

    def _show_totp_login_ui(self):
        """Standard daily TOTP login."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="🔐 Secure Login",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(50, 20))
        
        ctk.CTkLabel(
            self.container, text="Enter the 6-digit code from your\nAuthenticator app",
            text_color="gray"
        ).pack(pady=(0, 30))
        
        self.totp_entry = ctk.CTkEntry(
            self.container, width=200, height=50, 
            font=ctk.CTkFont(size=24, weight="bold"),
            justify="center", placeholder_text="      000 000"
        )
        self.totp_entry.pack(pady=10)
        
        self.login_btn = ctk.CTkButton(
            self.container, text="Unlock Vault",
            command=self._handle_tot_login, height=45,
            font=ctk.CTkFont(weight="bold")
        )
        self.login_btn.pack(pady=20, padx=50, fill="x")
        
        ctk.CTkLabel(self.container, text="OR", text_color="gray").pack()
        
        self.fallback_btn = ctk.CTkButton(
            self.container, text="Use Master Password (Recovery)",
            command=self._show_master_login_ui,
            fg_color="transparent", text_color="#3498db",
            hover_color=("#dfe6e9", "#2d3436")
        )
        self.fallback_btn.pack(pady=10)

        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack()

    def _show_master_login_ui(self):
        """Emergency Master Password recovery login."""
        for widget in self.container.winfo_children():
            widget.destroy()
            
        ctk.CTkLabel(
            self.container, text="🆘 Recovery Mode",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(40, 20))
        
        ctk.CTkLabel(
            self.container, text="Enter your recovery master password",
            text_color="gray"
        ).pack(pady=(0, 20))
        
        self.pass_entry = ctk.CTkEntry(self.container, show="•", width=300, placeholder_text="Master Password")
        self.pass_entry.pack(pady=10)
        
        self.recover_btn = ctk.CTkButton(
            self.container, text="Verify Master Password",
            command=self._handle_master_recovery, height=40
        )
        self.recover_btn.pack(pady=20)
        
        self.back_btn = ctk.CTkButton(
            self.container, text="← Back to TOTP",
            command=self._show_totp_login_ui,
            fg_color="transparent", text_color="gray"
        )
        self.back_btn.pack()

        self.error_label = ctk.CTkLabel(self.container, text="", text_color="#e74c3c")
        self.error_label.pack()

    def _handle_setup(self):
        password = self.pass_entry.get()
        confirm = self.confirm_entry.get()
        
        if password != confirm:
            self.error_label.configure(text="Passwords do not match")
            return
            
        if self.strength_meter.get_score() < 50:
            self.error_label.configure(text="Password is too weak")
            return
            
        self.on_setup(password)

    def _handle_tot_login(self):
        code = self.totp_entry.get().strip().replace(" ", "")
        if len(code) != 6:
            self.error_label.configure(text="Please enter 6 digits")
            return
            
        # The main app will handle verification and key derivation
        if not self.on_login(totp_code=code):
            self.error_label.configure(text="Invalid code. Try again.")

    def _handle_master_recovery(self):
        password = self.pass_entry.get()
        if not password:
            return
            
        # The main app will handle verification and show the Lost vs Temp prompt
        if not self.on_login(password=password):
            self.error_label.configure(text="Incorrect master password")
