"""
Key generator frame for cryptographic key generation.
"""
import customtkinter as ctk
from typing import Optional

from generators.key_generator import KeyGenerator, KeyType, KeyResult
from utils.clipboard import ClipboardManager


from config import COLOR_BG, COLOR_SURFACE, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM

class KeyGenFrame(ctk.CTkFrame):
    """Cryptographic key generator with modern interface."""
    
    def __init__(self, master, db_manager=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        self.db = db_manager
        self.generator = KeyGenerator()
        self.current_key: Optional[KeyResult] = None
        
        # Split pane
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_options_panel()
        self._create_preview_panel()
    
    def _create_options_panel(self):
        """Create left panel with key type options."""
        self.options_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.options_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # Header
        ctk.CTkLabel(
            self.options_frame, text="Algorithm Selection",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(padx=20, pady=(25, 20), anchor="w")
        
        content = ctk.CTkScrollableFrame(self.options_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        key_types = [
            (KeyType.RSA, "RSA", "Asymmetric, 3072/4096-bit"),
            (KeyType.ED25519, "Ed25519", "Modern, fast, 256-bit"),
            (KeyType.AES, "AES-256-GCM", "Symmetric encryption"),
            (KeyType.SSH_ED25519, "SSH (Ed25519)", "Secure Shell key pair"),
            (KeyType.SSH_RSA, "SSH (RSA)", "Legacy SSH compatibility"),
            (KeyType.X509, "X.509 Certificate", "Self-signed certificate"),
            (KeyType.HMAC, "HMAC Key", "Message authentication"),
            (KeyType.CHACHA20, "ChaCha20", "Fast symmetric stream"),
        ]
        
        self.selected_type = ctk.StringVar(value="RSA")
        
        for key_type, label, desc in key_types:
            frame = ctk.CTkFrame(content, fg_color=COLOR_BG, corner_radius=10, height=65)
            frame.pack(fill="x", pady=5)
            frame.pack_propagate(False)
            
            btn = ctk.CTkRadioButton(
                frame, text=label,
                variable=self.selected_type,
                value=key_type.value,
                font=ctk.CTkFont(weight="bold", size=13),
                fg_color=COLOR_ACCENT, border_color="#444444",
                command=self._on_type_change
            )
            btn.pack(side="left", padx=15)
            
            ctk.CTkLabel(
                frame, text=desc,
                font=ctk.CTkFont(size=11),
                text_color=COLOR_TEXT_DIM
            ).pack(side="right", padx=15)
        
        # Dynamic options area
        self.options_container = ctk.CTkFrame(content, fg_color="transparent")
        self.options_container.pack(fill="x", pady=15)
        
        # RSA
        self.rsa_options = ctk.CTkFrame(self.options_container, fg_color="transparent")
        ctk.CTkLabel(self.rsa_options, text="Key Size (bits)", font=ctk.CTkFont(weight="bold", size=12), text_color=COLOR_TEXT_DIM).pack(anchor="w")
        self.rsa_size = ctk.CTkComboBox(self.rsa_options, values=["3072", "4096"], width=120, fg_color=COLOR_BG, border_color="#333333")
        self.rsa_size.set("4096")
        self.rsa_size.pack(anchor="w", pady=5)
        
        # HMAC
        self.hmac_options = ctk.CTkFrame(self.options_container, fg_color="transparent")
        ctk.CTkLabel(self.hmac_options, text="Hash Algorithm", font=ctk.CTkFont(weight="bold", size=12), text_color=COLOR_TEXT_DIM).pack(anchor="w")
        self.hmac_algo = ctk.CTkComboBox(self.hmac_options, values=["SHA-256", "SHA-384", "SHA-512"], width=120, fg_color=COLOR_BG, border_color="#333333")
        self.hmac_algo.set("SHA-256")
        self.hmac_algo.pack(anchor="w", pady=5)
        
        # X.509
        self.x509_options = ctk.CTkFrame(self.options_container, fg_color="transparent")
        ctk.CTkLabel(self.x509_options, text="Common Name (CN)", font=ctk.CTkFont(weight="bold", size=12), text_color=COLOR_TEXT_DIM).pack(anchor="w")
        self.x509_cn = ctk.CTkEntry(self.x509_options, width=300, fg_color=COLOR_BG, border_color="#333333")
        self.x509_cn.insert(0, "CryptoPass Identity")
        self.x509_cn.pack(anchor="w", pady=5)
        self.x509_ed25519 = ctk.CTkCheckBox(self.x509_options, text="Modern Ed25519 Signature", fg_color=COLOR_ACCENT)
        self.x509_ed25519.select()
        self.x509_ed25519.pack(anchor="w", pady=10)
        
        self.generate_btn = ctk.CTkButton(
            content, text="Generate Cryptographic Key",
            height=50, fg_color=COLOR_ACCENT, text_color="black",
            font=ctk.CTkFont(weight="bold", size=14),
            command=self._generate
        )
        self.generate_btn.pack(fill="x", pady=(20, 0))

        self.import_btn = ctk.CTkButton(
            content, text="Import Certificate File",
            height=45, fg_color="transparent", border_width=1, border_color="#555555",
            text_color=COLOR_TEXT,
            command=self._import_certificate
        )
        self.import_btn.pack(fill="x", pady=(10, 0))
        
        self._on_type_change()
    
    def _create_preview_panel(self):
        """Create right panel with key preview."""
        self.preview_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.preview_frame.grid(row=0, column=1, sticky="nsew")
        
        content = ctk.CTkFrame(self.preview_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=30, pady=30)
        
        ctk.CTkLabel(
            content, text="Generated Output",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(0, 20))
        
        # Info
        self.info_label = ctk.CTkLabel(
            content, text="Select an algorithm to begin key generation.\nAll keys are generated locally and encrypted before storage.",
            text_color=COLOR_TEXT_DIM, justify="center", wraplength=300
        )
        self.info_label.pack(pady=100)
        
        # Public key
        self.public_frame = ctk.CTkFrame(content, fg_color="transparent")
        
        public_header = ctk.CTkFrame(self.public_frame, fg_color="transparent")
        public_header.pack(fill="x", pady=(0, 5))
        self.public_label = ctk.CTkLabel(public_header, text="Public Data", font=ctk.CTkFont(weight="bold", size=13), text_color=COLOR_TEXT_DIM)
        self.public_label.pack(side="left")
        
        self.copy_public_btn = ctk.CTkButton(
            public_header, text="📋 Copy", width=70, height=28,
            fg_color=COLOR_ACCENT, text_color="black", font=ctk.CTkFont(size=11, weight="bold"),
            command=lambda: self._copy_key("public")
        )
        self.copy_public_btn.pack(side="right")
        
        self.public_text = ctk.CTkTextbox(
            self.public_frame, height=130, fg_color=COLOR_BG,
            border_width=1, border_color="#333333",
            font=ctk.CTkFont(family="Consolas", size=11)
        )
        self.public_text.pack(fill="x")
        
        # Private key
        self.private_frame = ctk.CTkFrame(content, fg_color="transparent")
        
        private_header = ctk.CTkFrame(self.private_frame, fg_color="transparent")
        private_header.pack(fill="x", pady=(15, 5))
        ctk.CTkLabel(private_header, text="Private Secret", font=ctk.CTkFont(weight="bold", size=13), text_color=COLOR_TEXT_DIM).pack(side="left")
        
        btn_box = ctk.CTkFrame(private_header, fg_color="transparent")
        btn_box.pack(side="right")

        self.private_visible = False
        self.toggle_private_btn = ctk.CTkButton(
            btn_box, text="👁️ Show", width=70, height=28,
            fg_color="transparent", border_width=1, border_color="#555555",
            font=ctk.CTkFont(size=11),
            command=self._toggle_private_visibility
        )
        self.toggle_private_btn.pack(side="left", padx=5)

        self.copy_private_btn = ctk.CTkButton(
            btn_box, text="📋 Copy", width=70, height=28,
            fg_color="transparent", border_width=1, border_color="#555555",
            font=ctk.CTkFont(size=11),
            command=lambda: self._copy_key("private")
        )
        self.copy_private_btn.pack(side="left")
        
        self.private_text = ctk.CTkTextbox(
            self.private_frame, height=160, fg_color=COLOR_BG,
            border_width=1, border_color="#333333",
            font=ctk.CTkFont(family="Consolas", size=11)
        )
        self.private_text.pack(fill="x")
        
        # Action buttons
        self.action_frame = ctk.CTkFrame(content, fg_color="transparent")
        
        self.save_btn = ctk.CTkButton(
            self.action_frame, text="Store in Key Vault",
            height=45, fg_color="#3498db", hover_color="#2980b9",
            font=ctk.CTkFont(weight="bold"),
            command=self._save_to_vault
        )
        self.save_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.export_btn = ctk.CTkButton(
            self.action_frame, text="Download Files",
            height=45, fg_color="transparent", border_width=1, border_color="#555555",
            command=self._export_to_file
        )
        self.export_btn.pack(side="left", fill="x", expand=True)
    
    def _on_type_change(self):
        key_type = self.selected_type.get()
        self.rsa_options.pack_forget()
        self.hmac_options.pack_forget()
        self.x509_options.pack_forget()
        
        if key_type in ["RSA", "SSH-RSA"]:
            self.rsa_options.pack(fill="x")
        elif key_type == "HMAC":
            self.hmac_options.pack(fill="x")
        elif key_type == "X.509 Certificate":
            self.x509_options.pack(fill="x")
    
    def _generate(self):
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
            self.info_label.configure(text=f"Generation Failed: {str(e)}", text_color="#e74c3c")

    def _import_certificate(self):
        from tkinter import filedialog
        filepath = filedialog.askopenfilename(
            filetypes=[("PEM Certs", "*.pem *.crt *.cer"), ("All files", "*.*")],
            title="Import Certificate"
        )
        
        if filepath:
            try:
                with open(filepath, 'r') as f: cert_pem = f.read()
                metadata = KeyGenerator.parse_certificate(cert_pem)
                self.current_key = KeyResult(
                    key_type=KeyType.X509,
                    public_key=cert_pem,
                    private_key="",
                    key_size=0,
                    additional_info=metadata
                )
                self._display_key()
            except Exception as e:
                self.info_label.configure(text=f"Import Failed: {str(e)}", text_color="#e74c3c")
    
    def _display_key(self):
        if not self.current_key: return
        self.info_label.pack_forget()
        
        if self.current_key.key_type == KeyType.X509:
            self.public_label.configure(text="X.509 Certificate Content")
        elif "SSH" in self.current_key.key_type.value:
            self.public_label.configure(text="SSH Public Key")
        else:
            self.public_label.configure(text="Public Key Component")

        if self.current_key.public_key:
            self.public_frame.pack(fill="x")
            self.public_text.configure(state="normal")
            self.public_text.delete("1.0", "end")
            self.public_text.insert("1.0", self.current_key.public_key)
            self.public_text.configure(state="disabled")
        else:
            self.public_frame.pack_forget()
        
        self.private_frame.pack(fill="x")
        self.private_visible = False
        self.toggle_private_btn.configure(text="👁️ Show")
        self._update_private_display()
        self.action_frame.pack(fill="x", pady=(20, 0))

    def _toggle_private_visibility(self):
        self.private_visible = not self.private_visible
        self.toggle_private_btn.configure(text="👁️ Hide" if self.private_visible else "👁️ Show")
        self._update_private_display()

    def _update_private_display(self):
        if not self.current_key: return
        self.private_text.configure(state="normal")
        self.private_text.delete("1.0", "end")
        if self.private_visible:
            self.private_text.insert("1.0", self.current_key.private_key)
        else:
            lines = self.current_key.private_key.splitlines()
            if len(lines) > 2:
                masked = f"{lines[0]}\n\n[ SENSITIVE PRIVATE KEY MASKED ]\n\n{lines[-1]}"
            else:
                masked = "[ SENSITIVE PRIVATE KEY MASKED ]"
            self.private_text.insert("1.0", masked)
        self.private_text.configure(state="disabled")
    
    def _copy_key(self, key_type: str):
        if not self.current_key: return
        btn = self.copy_public_btn if key_type == "public" else self.copy_private_btn
        text = self.current_key.public_key if key_type == "public" else self.current_key.private_key
        
        if text:
            ClipboardManager.copy(text)
            btn.configure(text="✓ Copied")
            self.after(2000, lambda: btn.configure(text="📋 Copy"))
    
    def _save_to_vault(self):
        if not self.current_key or not self.db: return
        
        dialog = ctk.CTkInputDialog(text="Enter a unique name for this entry:", title="Vault Entry")
        name = dialog.get_input()
        
        if name:
            expiry = None
            metadata = None
            if self.current_key.key_type == KeyType.X509:
                metadata = self.current_key.additional_info
                expiry = metadata.get('expiry_date') if metadata else None

            self.db.add_crypto_key(
                name=name,
                key_type=self.current_key.key_type.value,
                public_key=self.current_key.public_key,
                private_key=self.current_key.private_key,
                key_size=self.current_key.key_size,
                expiry_date=expiry,
                metadata=metadata
            )
            self.save_btn.configure(text="Vault Entry Created!", state="disabled")
            self.after(2000, lambda: self.save_btn.configure(text="Store in Key Vault", state="normal"))
    
    def _export_to_file(self):
        if not self.current_key: return
        from tkinter import filedialog
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM File", "*.pem"), ("All files", "*.*")],
            title="Download Cryptographic Files"
        )
        if filepath:
            base = filepath.rsplit('.', 1)[0]
            KeyGenerator.export_to_file(self.current_key, base)
