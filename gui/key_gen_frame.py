"""
Key generator frame for cryptographic key generation.
"""
import customtkinter as ctk
from typing import Optional

from generators.key_generator import KeyGenerator, KeyType, KeyResult
from utils.clipboard import ClipboardManager


class KeyGenFrame(ctk.CTkFrame):
    """Cryptographic key generator interface."""
    
    def __init__(self, master, db_manager=None, **kwargs):
        super().__init__(master, **kwargs)
        
        self.db = db_manager
        self.generator = KeyGenerator()
        self.current_key: Optional[KeyResult] = None
        
        self.configure(fg_color="transparent")
        
        # Split pane
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_options_panel()
        self._create_preview_panel()
    
    def _create_options_panel(self):
        """Create left panel with key type options."""
        self.options_frame = ctk.CTkFrame(self)
        self.options_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        # Header
        ctk.CTkLabel(
            self.options_frame, text="🔐 Key Type",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(padx=15, pady=15, anchor="w")
        
        content = ctk.CTkScrollableFrame(self.options_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Key type buttons
        key_types = [
            (KeyType.RSA, "🔑 RSA", "Asymmetric, 3072/4096-bit"),
            (KeyType.ED25519, "✨ Ed25519", "Modern, fast, 256-bit"),
            (KeyType.AES, "🔒 AES-256-GCM", "Symmetric encryption"),
            (KeyType.SSH_ED25519, "🖥️ SSH (Ed25519)", "SSH key pair"),
            (KeyType.SSH_RSA, "🖥️ SSH (RSA)", "SSH key pair, 4096-bit"),
            (KeyType.X509, "📜 X.509 Certificate", "Self-signed cert"),
            (KeyType.HMAC, "🏷️ HMAC Key", "Message authentication"),
            (KeyType.CHACHA20, "⚡ ChaCha20-Poly1305", "Symmetric, 256-bit"),
        ]
        
        self.selected_type = ctk.StringVar(value="RSA")
        
        for key_type, label, desc in key_types:
            frame = ctk.CTkFrame(content, fg_color="transparent")
            frame.pack(fill="x", pady=5)
            
            btn = ctk.CTkRadioButton(
                frame, text=label,
                variable=self.selected_type,
                value=key_type.value,
                command=self._on_type_change
            )
            btn.pack(anchor="w")
            
            ctk.CTkLabel(
                frame, text=desc,
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(anchor="w", padx=(25, 0))
        
        # RSA size option
        self.rsa_options = ctk.CTkFrame(content, fg_color="transparent")
        self.rsa_options.pack(fill="x", pady=(15, 0))
        
        ctk.CTkLabel(self.rsa_options, text="RSA Key Size").pack(anchor="w")
        self.rsa_size = ctk.CTkComboBox(
            self.rsa_options,
            values=["3072", "4096"],
            width=120
        )
        self.rsa_size.set("4096")
        self.rsa_size.pack(anchor="w", pady=5)
        
        # HMAC algorithm option
        self.hmac_options = ctk.CTkFrame(content, fg_color="transparent")
        
        ctk.CTkLabel(self.hmac_options, text="Hash Algorithm").pack(anchor="w")
        self.hmac_algo = ctk.CTkComboBox(
            self.hmac_options,
            values=["SHA-256", "SHA-384", "SHA-512"],
            width=120
        )
        self.hmac_algo.set("SHA-256")
        self.hmac_algo.pack(anchor="w", pady=5)
        
        # X.509 options
        self.x509_options = ctk.CTkFrame(content, fg_color="transparent")
        
        ctk.CTkLabel(self.x509_options, text="Common Name").pack(anchor="w")
        self.x509_cn = ctk.CTkEntry(self.x509_options, width=200)
        self.x509_cn.insert(0, "CryptoPass Self-Signed")
        self.x509_cn.pack(anchor="w", pady=5)
        
        self.x509_ed25519 = ctk.CTkCheckBox(
            self.x509_options, text="Use Ed25519 (vs RSA-4096)"
        )
        self.x509_ed25519.select()
        self.x509_ed25519.pack(anchor="w", pady=5)
        
        # Generate button
        self.generate_btn = ctk.CTkButton(
            content, text="⚡ Generate Key",
            height=45, font=ctk.CTkFont(size=14, weight="bold"),
            command=self._generate
        )
        self.generate_btn.pack(fill="x", pady=(20, 0))
    
    def _create_preview_panel(self):
        """Create right panel with key preview."""
        self.preview_frame = ctk.CTkFrame(self)
        self.preview_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        
        # Header
        ctk.CTkLabel(
            self.preview_frame, text="📋 Generated Key",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(padx=15, pady=15, anchor="w")
        
        content = ctk.CTkFrame(self.preview_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Key info
        self.info_label = ctk.CTkLabel(
            content, text="Select a key type and click Generate",
            text_color="gray"
        )
        self.info_label.pack(pady=20)
        
        # Public key
        self.public_frame = ctk.CTkFrame(content, fg_color="transparent")
        
        public_header = ctk.CTkFrame(self.public_frame, fg_color="transparent")
        public_header.pack(fill="x")
        ctk.CTkLabel(public_header, text="Public Key / Certificate").pack(side="left")
        self.copy_public_btn = ctk.CTkButton(
            public_header, text="📋 Copy", width=70,
            command=lambda: self._copy_key("public")
        )
        self.copy_public_btn.pack(side="right")
        
        self.public_text = ctk.CTkTextbox(self.public_frame, height=120)
        self.public_text.pack(fill="x", pady=(5, 15))
        
        # Private key
        self.private_frame = ctk.CTkFrame(content, fg_color="transparent")
        
        private_header = ctk.CTkFrame(self.private_frame, fg_color="transparent")
        private_header.pack(fill="x")
        ctk.CTkLabel(private_header, text="Private Key / Secret").pack(side="left")
        self.copy_private_btn = ctk.CTkButton(
            private_header, text="📋 Copy", width=70,
            command=lambda: self._copy_key("private")
        )
        self.copy_private_btn.pack(side="right")
        
        self.private_text = ctk.CTkTextbox(self.private_frame, height=150)
        self.private_text.pack(fill="x", pady=(5, 15))
        
        # Action buttons
        self.action_frame = ctk.CTkFrame(content, fg_color="transparent")
        
        self.save_btn = ctk.CTkButton(
            self.action_frame, text="💾 Save to Vault",
            command=self._save_to_vault
        )
        self.save_btn.pack(side="left", padx=(0, 10))
        
        self.export_btn = ctk.CTkButton(
            self.action_frame, text="📁 Export to File",
            command=self._export_to_file
        )
        self.export_btn.pack(side="left")
    
    def _on_type_change(self):
        """Handle key type selection change."""
        key_type = self.selected_type.get()
        
        # Hide all options
        self.rsa_options.pack_forget()
        self.hmac_options.pack_forget()
        self.x509_options.pack_forget()
        
        # Show relevant options
        if key_type in ["RSA", "SSH-RSA"]:
            self.rsa_options.pack(fill="x", pady=(15, 0))
        elif key_type == "HMAC":
            self.hmac_options.pack(fill="x", pady=(15, 0))
        elif key_type == "X.509 Certificate":
            self.x509_options.pack(fill="x", pady=(15, 0))
    
    def _generate(self):
        """Generate the selected key type."""
        key_type_str = self.selected_type.get()
        key_type = KeyType(key_type_str)
        
        kwargs = {}
        
        if key_type in [KeyType.RSA, KeyType.SSH_RSA]:
            kwargs['key_size'] = int(self.rsa_size.get())
        elif key_type == KeyType.HMAC:
            kwargs['hash_algorithm'] = self.hmac_algo.get()
        elif key_type == KeyType.X509:
            kwargs['common_name'] = self.x509_cn.get()
            kwargs['use_ed25519'] = bool(self.x509_ed25519.get())
        
        try:
            self.current_key = self.generator.generate(key_type, **kwargs)
            self._display_key()
        except Exception as e:
            self.info_label.configure(text=f"Error: {str(e)}", text_color="#e74c3c")
    
    def _display_key(self):
        """Display the generated key."""
        if not self.current_key:
            return
        
        # Hide info label, show key fields
        self.info_label.pack_forget()
        
        # Show/hide public key based on key type
        if self.current_key.public_key:
            self.public_frame.pack(fill="x")
            self.public_text.delete("1.0", "end")
            self.public_text.insert("1.0", self.current_key.public_key)
        else:
            self.public_frame.pack_forget()
        
        # Show private key
        self.private_frame.pack(fill="x")
        self.private_text.delete("1.0", "end")
        self.private_text.insert("1.0", self.current_key.private_key)
        
        # Show action buttons
        self.action_frame.pack(fill="x", pady=(10, 0))
    
    def _copy_key(self, key_type: str):
        """Copy key to clipboard."""
        if not self.current_key:
            return
        
        if key_type == "public":
            ClipboardManager.copy(self.current_key.public_key)
            self.copy_public_btn.configure(text="✓ Copied!")
            self.after(2000, lambda: self.copy_public_btn.configure(text="📋 Copy"))
        else:
            ClipboardManager.copy(self.current_key.private_key)
            self.copy_private_btn.configure(text="✓ Copied!")
            self.after(2000, lambda: self.copy_private_btn.configure(text="📋 Copy"))
    
    def _save_to_vault(self):
        """Save key to vault."""
        if not self.current_key or not self.db:
            return
        
        dialog = ctk.CTkInputDialog(
            text="Enter a name for this key:",
            title="Save Key"
        )
        name = dialog.get_input()
        
        if name:
            self.db.add_crypto_key(
                name=name,
                key_type=self.current_key.key_type.value,
                public_key=self.current_key.public_key,
                private_key=self.current_key.private_key,
                key_size=self.current_key.key_size
            )
    
    def _export_to_file(self):
        """Export key to file."""
        if not self.current_key:
            return
        
        from tkinter import filedialog
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            title="Export Key"
        )
        
        if filepath:
            # Remove extension for the helper
            base = filepath.rsplit('.', 1)[0]
            KeyGenerator.export_to_file(self.current_key, base)
