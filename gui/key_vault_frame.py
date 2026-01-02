"""
Key vault frame for viewing and managing cryptographic keys and certificates.
"""
import customtkinter as ctk
from typing import List, Dict, Any, Optional
from datetime import datetime

from utils.clipboard import ClipboardManager
from generators.key_generator import KeyGenerator, KeyType, KeyResult

class KeyVaultFrame(ctk.CTkFrame):
    """View and manage saved cryptographic keys and certificates."""
    
    def __init__(self, master, db_manager, **kwargs):
        super().__init__(master, **kwargs)
        
        self.db = db_manager
        self.keys: List[Dict[str, Any]] = []
        self.selected_id: Optional[int] = None
        
        self.configure(fg_color="transparent")
        
        # Split pane
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_list_panel()
        self._create_detail_panel()
    
    def _create_list_panel(self):
        """Create left panel with keys list."""
        self.list_frame = ctk.CTkFrame(self)
        self.list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        # Header
        header = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=15)
        
        ctk.CTkLabel(
            header, text="📜 Key & Cert Vault",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(side="left")
        
        # Search
        self.search_entry = ctk.CTkEntry(
            self.list_frame, placeholder_text="🔍 Search keys...",
            height=35
        )
        self.search_entry.pack(fill="x", padx=10, pady=(0, 10))
        self.search_entry.bind("<KeyRelease>", self._on_search)
        
        # Scrollable list
        self.list_scroll = ctk.CTkScrollableFrame(self.list_frame)
        self.list_scroll.pack(fill="both", expand=True, padx=5, pady=5)
    
    def _create_detail_panel(self):
        """Create right panel with key details."""
        self.detail_frame = ctk.CTkFrame(self)
        self.detail_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        
        # Content area
        self.detail_content = ctk.CTkScrollableFrame(self.detail_frame, fg_color="transparent")
        self.detail_content.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Empty state
        self.empty_label = ctk.CTkLabel(
            self.detail_content,
            text="Select a key or certificate from the list",
            text_color="gray"
        )
        self.empty_label.pack(expand=True, pady=100)
        
        # Detail area (hidden initially)
        self.data_frame = ctk.CTkFrame(self.detail_content, fg_color="transparent")
        
        self.title_label = ctk.CTkLabel(
            self.data_frame, text="",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.title_label.pack(anchor="w", pady=(0, 5))
        
        self.type_badge = ctk.CTkLabel(
            self.data_frame, text="",
            font=ctk.CTkFont(size=12),
            fg_color="#34495e", corner_radius=5
        )
        self.type_badge.pack(anchor="w", pady=(0, 15))
        
        # Metadata area
        self.meta_frame = ctk.CTkFrame(self.data_frame, fg_color="transparent")
        self.meta_frame.pack(fill="x", pady=10)
        
        # Keys area
        self.keys_area = ctk.CTkFrame(self.data_frame, fg_color="transparent")
        self.keys_area.pack(fill="x", pady=10)
        
        self._create_key_field("public", "Public Key / Certificate")
        self._create_key_field("private", "Private Key / Secret")
        
        # Actions
        self.actions_frame = ctk.CTkFrame(self.data_frame, fg_color="transparent")
        self.actions_frame.pack(fill="x", pady=20)
        
        self.delete_btn = ctk.CTkButton(
            self.actions_frame, text="🗑️ Delete from Vault",
            fg_color="#e74c3c", hover_color="#c0392b",
            command=self._delete_key
        )
        self.delete_btn.pack(side="left")
    
    def _create_key_field(self, name: str, label: str):
        frame = ctk.CTkFrame(self.keys_area, fg_color="transparent")
        frame.pack(fill="x", pady=5)
        
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x")
        label_obj = ctk.CTkLabel(header, text=label, font=ctk.CTkFont(weight="bold"))
        label_obj.pack(side="left")
        setattr(self, f"{name}_label", label_obj)
        
        if name == "private":
            self.private_visible = False
            toggle_btn = ctk.CTkButton(
                header, text="👁️ Show", width=65, height=25,
                fg_color="transparent", border_width=1,
                command=self._toggle_private_visibility
            )
            toggle_btn.pack(side="right", padx=(0, 5))
            self.toggle_private_btn = toggle_btn

        copy_btn = ctk.CTkButton(
            header, text="📋 Copy", width=60, height=25,
            command=lambda n=name: self._copy_key(n)
        )
        copy_btn.pack(side="right")
        
        text = ctk.CTkTextbox(frame, height=150)
        text.pack(fill="x", pady=5)
        setattr(self, f"{name}_text", text)
        setattr(self, f"{name}_frame", frame)
    
    def _create_meta_row(self, label: str, value: str, color: str = "white"):
        row = ctk.CTkFrame(self.meta_frame, fg_color="transparent")
        row.pack(fill="x", pady=2)
        ctk.CTkLabel(row, text=f"{label}:", font=ctk.CTkFont(weight="bold"), width=120, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=value, text_color=color, anchor="w").pack(side="left", fill="x", expand=True)

    def refresh(self):
        """Refresh keys list."""
        self.keys = self.db.get_all_crypto_keys()
        self._update_list()
    
    def _update_list(self, filter_text: str = ""):
        for widget in self.list_scroll.winfo_children():
            widget.destroy()
        
        keys = self.keys
        if filter_text:
            filter_lower = filter_text.lower()
            keys = [k for k in keys if filter_lower in k['name'].lower()]
            
        for key in keys:
            self._create_list_item(key)
            
        if not keys:
            ctk.CTkLabel(self.list_scroll, text="No keys found", text_color="gray").pack(pady=20)
            
    def _create_list_item(self, key: Dict[str, Any]):
        item = ctk.CTkFrame(self.list_scroll, height=60, cursor="hand2")
        item.pack(fill="x", pady=2)
        item.pack_propagate(False)
        
        icon = "📜" if key['key_type'] == "X.509 Certificate" else "🔑"
        
        content = ctk.CTkFrame(item, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=10, pady=8)
        
        ctk.CTkLabel(content, text=f"{icon} {key['name']}", 
                    font=ctk.CTkFont(size=14, weight="bold"), anchor="w").pack(fill="x")
        
        ctk.CTkLabel(content, text=key['key_type'], 
                    font=ctk.CTkFont(size=11), text_color="gray", anchor="w").pack(fill="x")
        
        for widget in [item, content] + list(content.winfo_children()):
            widget.bind("<Button-1>", lambda e, k=key: self._select_key(k))
            
    def _select_key(self, key_summary: Dict[str, Any]):
        key = self.db.get_crypto_key(key_summary['id'])
        if not key: return
        
        self.selected_id = key['id']
        self.current_key_data = key # Store raw data
        
        self.empty_label.pack_forget()
        self.data_frame.pack(fill="both", expand=True)
        
        self.title_label.configure(text=key['name'])
        self.type_badge.configure(text=f"  {key['key_type']}  ")
        
        # Standardize labels
        if key['key_type'] == "X.509 Certificate":
            self.public_label.configure(text="📜 X.509 Certificate (PEM)")
        elif "SSH" in key['key_type']:
            self.public_label.configure(text="📋 SSH Public Key")
        else:
            self.public_label.configure(text="🔑 Public Key")
        self.private_label.configure(text="🔒 Private Key")

        # Update metadata
        for widget in self.meta_frame.winfo_children(): widget.destroy()
        
        if key['expiry_date']:
            expiry = datetime.fromisoformat(key['expiry_date'])
            is_expired = expiry < datetime.utcnow()
            color = "#e74c3c" if is_expired else "#2ecc71"
            self._create_meta_row("Expires", expiry.strftime("%Y-%m-%d %H:%M"), color)
            
        if key['metadata']:
            for k, v in key['metadata'].items():
                if k != "expiry_date":
                    label = k.replace('_', ' ').title()
                    self._create_meta_row(label, str(v))
                    
        self._create_meta_row("Created", key['created_at'])
        
        # Update keys
        self._update_text_field("public", key['public_key'])
        
        # Reset visibility and update private field
        self.private_visible = False
        self.toggle_private_btn.configure(text="👁️ Show")
        self._update_private_display()
        
    def _update_private_display(self):
        """Update the private key text box based on visibility."""
        if not hasattr(self, 'current_key_data') or not self.current_key_data:
            self.private_frame.pack_forget()
            return
            
        value = self.current_key_data.get('private_key')
        if not value:
            self.private_frame.pack_forget()
            return
            
        self.private_frame.pack(fill="x", pady=5)
        self.private_text.delete("1.0", "end")
        
        if self.private_visible:
            self.private_text.insert("1.0", value)
        else:
            lines = value.splitlines()
            if len(lines) > 2:
                masked = f"{lines[0]}\n[ SENSITIVE PRIVATE KEY MASKED ]\n{lines[-1]}"
            else:
                masked = "[ SENSITIVE PRIVATE KEY MASKED ]"
            self.private_text.insert("1.0", masked)

    def _toggle_private_visibility(self):
        """Toggle private key visibility."""
        self.private_visible = not self.private_visible
        self.toggle_private_btn.configure(text="👁️ Hide" if self.private_visible else "👁️ Show")
        self._update_private_display()

    def _update_text_field(self, name: str, value: str):
        frame = getattr(self, f"{name}_frame")
        text = getattr(self, f"{name}_text")
        if value:
            frame.pack(fill="x", pady=5)
            text.delete("1.0", "end")
            text.insert("1.0", value)
        else:
            frame.pack_forget()
            
    def _copy_key(self, name: str):
        """Copy actual raw key even if masked."""
        if name == "private" and hasattr(self, 'current_key_data'):
            text = self.current_key_data.get('private_key', "").strip()
        else:
            text = getattr(self, f"{name}_text").get("1.0", "end").strip()
            
        if text and not text.startswith("[ SENSITIVE"):
            ClipboardManager.copy(text)
        elif name == "private":
            ClipboardManager.copy(self.current_key_data.get('private_key', ""))

    def _delete_key(self):
        if self.selected_id:
            dialog = ctk.CTkInputDialog(text="Type 'DELETE' to confirm:", title="Confirm Delete")
            if dialog.get_input() == "DELETE":
                self.db.delete_crypto_key(self.selected_id)
                self.selected_id = None
                self.data_frame.pack_forget()
                self.empty_label.pack(expand=True, pady=100)
                self.refresh()

    def _on_search(self, event=None):
        query = self.search_entry.get()
        self._update_list(query)
