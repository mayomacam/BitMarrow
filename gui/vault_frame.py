<<<<<<< HEAD
"""
Password vault frame for viewing and managing passwords.
"""
import customtkinter as ctk
from typing import Callable, List, Dict, Any, Optional

from utils.clipboard import ClipboardManager


from config import COLOR_BG, COLOR_SURFACE, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM

class VaultFrame(ctk.CTkFrame):
    """Password vault with modern card-based interface."""
    
    def __init__(self, master, db_manager, on_refresh: Callable = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        self.db = db_manager
        self.on_refresh = on_refresh
        self.passwords: List[Dict[str, Any]] = []
        self.selected_id: Optional[int] = None
        
        # Split pane
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_list_panel()
        self._create_detail_panel()
    
    def _create_list_panel(self):
        """Create left panel with password list."""
        self.list_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # Header
        header = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=20)
        
        ctk.CTkLabel(
            header, text="Your Passwords",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left")
        
        self.add_btn = ctk.CTkButton(
            header, text="+ Add New", width=100, height=32,
            fg_color=COLOR_ACCENT, text_color="black",
            hover_color="#27ae60",
            font=ctk.CTkFont(weight="bold"),
            command=self._show_add_dialog
        )
        self.add_btn.pack(side="right")
        
        # Search
        search_frame = ctk.CTkFrame(self.list_frame, fg_color=COLOR_BG, corner_radius=10, height=45)
        search_frame.pack(fill="x", padx=15, pady=(0, 15))
        search_frame.pack_propagate(False)
        
        self.search_entry = ctk.CTkEntry(
            search_frame, placeholder_text="🔍 Search passwords...",
            fg_color="transparent", border_width=0,
            font=ctk.CTkFont(size=13)
        )
        self.search_entry.pack(fill="both", expand=True, padx=10)
        self.search_entry.bind("<KeyRelease>", self._on_search)
        
        # Scrollable list
        self.list_scroll = ctk.CTkScrollableFrame(self.list_frame, fg_color="transparent")
        self.list_scroll.pack(fill="both", expand=True, padx=5, pady=5)
    
    def _create_detail_panel(self):
        """Create right panel with password details."""
        self.detail_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.detail_frame.grid(row=0, column=1, sticky="nsew")
        
        # Header
        self.detail_header = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.detail_header.pack(fill="x", padx=25, pady=20)
        
        self.detail_title = ctk.CTkLabel(
            self.detail_header, text="Select an entry",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.detail_title.pack(side="left")
        
        # Action buttons (hidden initially)
        self.action_frame = ctk.CTkFrame(self.detail_header, fg_color="transparent")
        self.action_frame.pack(side="right")
        
        self.edit_btn = ctk.CTkButton(
            self.action_frame, text="Edit", width=80, height=32,
            fg_color="#3498db", hover_color="#2980b9",
            command=self._edit_password
        )
        
        self.delete_btn = ctk.CTkButton(
            self.action_frame, text="Delete", width=80, height=32,
            fg_color="transparent", border_width=1, border_color="#e74c3c",
            text_color="#e74c3c", hover_color="#c0392b",
            command=self._delete_password
        )
        
        # Content area
        self.detail_content = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.detail_content.pack(fill="both", expand=True, padx=25)
        
        # Empty state
        self.empty_label = ctk.CTkLabel(
            self.detail_content,
            text="Choose a password from the list to view its details\nor click '+ Add New' to create one.",
            text_color=COLOR_TEXT_DIM,
            font=ctk.CTkFont(size=14),
            wraplength=300
        )
        self.empty_label.pack(expand=True)
        
        # Detail fields (hidden initially)
        self.fields_frame = ctk.CTkFrame(self.detail_content, fg_color="transparent")
        
        self._create_field("username", "👤 Username")
        self._create_field("password", "🔑 Password", is_password=True)
        self._create_field("url", "🌐 Website / URL")
        self._create_field("category", "📁 Folder / Category")
        self._create_field("notes", "📝 Notes", is_textbox=True)
    
    def _create_field(self, name: str, label: str, 
                       is_password: bool = False, is_textbox: bool = False):
        """Create a styled detail field."""
        frame = ctk.CTkFrame(self.fields_frame, fg_color="transparent")
        frame.pack(fill="x", pady=12)
        
        ctk.CTkLabel(
            frame, text=label, 
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLOR_TEXT_DIM
        ).pack(anchor="w", pady=(0, 5))
        
        field_row = ctk.CTkFrame(frame, fg_color=COLOR_BG, corner_radius=10, height=45)
        field_row.pack(fill="x")
        field_row.pack_propagate(False)
        
        if is_textbox:
            field_row.configure(height=120)
            widget = ctk.CTkTextbox(field_row, fg_color="transparent", border_width=0, state="disabled")
            widget.pack(side="left", fill="both", expand=True, padx=10, pady=5)
        else:
            widget = ctk.CTkEntry(field_row, fg_color="transparent", border_width=0, state="disabled")
            if is_password:
                widget.configure(show="•")
            widget.pack(side="left", fill="both", expand=True, padx=10)
        
        # Copy button
        copy_btn = ctk.CTkButton(
            field_row, text="📋", width=35, height=35,
            fg_color="transparent", hover_color="#333333",
            command=lambda n=name: self._copy_field(n)
        )
        copy_btn.pack(side="right", padx=5)
        
        # Show/hide for password
        if is_password:
            self.show_pass_btn = ctk.CTkButton(
                field_row, text="👁", width=35, height=35,
                fg_color="transparent", hover_color="#333333",
                command=self._toggle_password_visibility
            )
            self.show_pass_btn.pack(side="right")
            self.password_visible = False
        
        setattr(self, f"field_{name}", widget)
    
    def _toggle_password_visibility(self):
        """Toggle password field visibility."""
        self.password_visible = not self.password_visible
        self.field_password.configure(show="" if self.password_visible else "•")
        self.show_pass_btn.configure(text="🔒" if self.password_visible else "👁")
    
    def _copy_field(self, field_name: str):
        """Copy field value to clipboard."""
        widget = getattr(self, f"field_{field_name}", None)
        if widget:
            if isinstance(widget, ctk.CTkTextbox):
                value = widget.get("1.0", "end").strip()
            else:
                widget.configure(state="normal")
                value = widget.get()
                widget.configure(state="disabled")
            
            if value:
                ClipboardManager.copy(value)
    
    def refresh(self):
        """Refresh password list."""
        self.passwords = self.db.get_all_passwords()
        self._update_list()
    
    def _update_list(self, filter_text: str = ""):
        """Update the password list display."""
        for widget in self.list_scroll.winfo_children():
            widget.destroy()
        
        passwords = self.passwords
        if filter_text:
            filter_lower = filter_text.lower()
            passwords = [
                p for p in passwords
                if filter_lower in p['title'].lower() or
                   filter_lower in (p['username'] or '').lower()
            ]
        
        for pwd in passwords:
            self._create_list_item(pwd)
        
        if not passwords:
            ctk.CTkLabel(
                self.list_scroll, text="No matches found",
                text_color=COLOR_TEXT_DIM,
                pady=40
            ).pack()
    
    def _create_list_item(self, password: Dict[str, Any]):
        """Create a styled password list item."""
        is_selected = self.selected_id == password['id']
        bg_color = "#333333" if is_selected else "transparent"
        
        item = ctk.CTkFrame(self.list_scroll, height=70, fg_color=bg_color, cursor="hand2", corner_radius=10)
        item.pack(fill="x", pady=4, padx=5)
        item.pack_propagate(False)
        
        icons = {
            "email": "📧", "bank": "🏦", "social": "👥",
            "work": "💼", "shopping": "🛒", "": "🔐"
        }
        category = (password.get('category') or '').lower()
        icon = icons.get(category, "🔐")
        
        content = ctk.CTkFrame(item, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=10)
        
        ctk.CTkLabel(
            content, text=f"{icon}  {password['title']}",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
            text_color=COLOR_TEXT
        ).pack(fill="x")
        
        ctk.CTkLabel(
            content, text=password.get('username', 'No username'),
            font=ctk.CTkFont(size=12),
            text_color=COLOR_TEXT_DIM,
            anchor="w"
        ).pack(fill="x")
        
        # Bind click
        def handle_click(e):
            self._select_password(password)
            self._update_list(self.search_entry.get()) # Highlight change
            
        for widget in [item, content] + list(content.winfo_children()):
            widget.bind("<Button-1>", handle_click)
    
    def _select_password(self, password: Dict[str, Any]):
        """Select and display password details."""
        self.selected_id = password['id']
        
        self.detail_title.configure(text=password['title'])
        self.edit_btn.pack(side="left", padx=5)
        self.delete_btn.pack(side="left", padx=5)
        
        self.empty_label.pack_forget()
        self.fields_frame.pack(fill="both", expand=True, pady=10)
        
        self._update_field("username", password.get('username', ''))
        self._update_field("password", password.get('password', ''))
        self._update_field("url", password.get('url', ''))
        self._update_field("notes", password.get('notes', ''))
        self._update_field("category", password.get('category', ''))
        
        self.password_visible = False
        self.field_password.configure(show="•")
        self.show_pass_btn.configure(text="👁")
    
    def _update_field(self, name: str, value: str):
        widget = getattr(self, f"field_{name}", None)
        if widget:
            if isinstance(widget, ctk.CTkTextbox):
                widget.configure(state="normal")
                widget.delete("1.0", "end")
                widget.insert("1.0", value or "")
                widget.configure(state="disabled")
            else:
                widget.configure(state="normal")
                widget.delete(0, "end")
                widget.insert(0, value or "")
                widget.configure(state="disabled")
    
    def _on_search(self, event=None):
        self._update_list(self.search_entry.get())
    
    def _show_add_dialog(self):
        dialog = PasswordDialog(self, "Add Password", self._save_new_password)
        dialog.focus()
    
    def _edit_password(self):
        if self.selected_id:
            password = self.db.get_password(self.selected_id)
            if password:
                dialog = PasswordDialog(
                    self, "Edit Password",
                    lambda data: self._save_edited_password(self.selected_id, data),
                    password
                )
                dialog.focus()
    
    def _save_new_password(self, data: Dict[str, str]):
        self.db.add_password(**data)
        self.refresh()
    
    def _save_edited_password(self, entry_id: int, data: Dict[str, str]):
        self.db.update_password(entry_id, **data)
        self.refresh()
        password = self.db.get_password(entry_id)
        if password:
            self._select_password(password)
    
    def _delete_password(self):
        if self.selected_id:
            dialog = ctk.CTkInputDialog(
                text="Type 'DELETE' to confirm deletion:",
                title="Confirm Delete"
            )
            result = dialog.get_input()
            if result == "DELETE":
                self.db.delete_password(self.selected_id)
                self.selected_id = None
                self.refresh()
                self.detail_title.configure(text="Select an entry")
                self.edit_btn.pack_forget()
                self.delete_btn.pack_forget()
                self.fields_frame.pack_forget()
                self.empty_label.pack(expand=True)


class PasswordDialog(ctk.CTkToplevel):
    """Modern dialog for adding/editing passwords."""
    
    def __init__(self, parent, title: str, on_save: Callable,
                 initial_data: Dict[str, Any] = None):
        super().__init__(parent)
        
        self.on_save = on_save
        self.initial_data = initial_data or {}
        
        self.title(title)
        self.geometry("450x600")
        self.resizable(False, False)
        self.configure(fg_color=COLOR_BG)
        
        self.transient(parent)
        self.grab_set()
        
        self._create_form()
    
    def _create_form(self):
        content = ctk.CTkScrollableFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Helper for fields
        def add_entry(label, name, is_password=False):
            ctk.CTkLabel(content, text=label, font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 5))
            entry = ctk.CTkEntry(content, width=380, height=40, fg_color=COLOR_SURFACE, border_color="#333333")
            if is_password: entry.configure(show="•")
            entry.pack(pady=(0, 20))
            entry.insert(0, self.initial_data.get(name, ''))
            return entry

        self.title_entry = add_entry("Title *", 'title')
        self.username_entry = add_entry("Username", 'username')
        
        ctk.CTkLabel(content, text="Password *", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 5))
        
        pass_row = ctk.CTkFrame(content, fg_color="transparent")
        pass_row.pack(fill="x", pady=(0, 10))
        
        self.password_entry = ctk.CTkEntry(pass_row, width=330, height=40, fg_color=COLOR_SURFACE, border_color="#333333", show="•")
        self.password_entry.pack(side="left")
        self.password_entry.insert(0, self.initial_data.get('password', ''))
        
        self.pass_visible = False
        self.toggle_btn = ctk.CTkButton(
            pass_row, text="👁", width=42, height=40,
            fg_color=COLOR_SURFACE, border_width=1, border_color="#333333",
            hover_color="#333333",
            command=self._toggle_pass
        )
        self.toggle_btn.pack(side="right")
        
        ctk.CTkButton(
            content, text="⚡ Generate Strong Password", width=380, height=35,
            fg_color="transparent", border_width=1, border_color=COLOR_ACCENT,
            text_color=COLOR_ACCENT, hover_color="#222222",
            command=self._generate_password
        ).pack(pady=(0, 20))
        
        self.url_entry = add_entry("Website / URL", 'url')
        
        ctk.CTkLabel(content, text="Category", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 5))
        
        # Dynamic categories from DB + defaults
        default_categories = ["Email", "Social", "Finance", "Work", "Utilities", "Shopping"]
        db_categories = []
        try:
            db_categories = self.master.db.get_unique_categories()
        except: pass
        
        # Merge and dedup
        category_options = sorted(list(set(default_categories + db_categories)))
        category_options.insert(0, "") # Add empty option
        
        self.category_combo = ctk.CTkComboBox(
            content, width=380, height=40, fg_color=COLOR_SURFACE, border_color="#333333",
            values=category_options
        )
        self.category_combo.pack(pady=(0, 5))
        
        ctk.CTkLabel(
            content, text="Tip: Select or type a new category",
            font=ctk.CTkFont(size=11), text_color=COLOR_TEXT_DIM
        ).pack(anchor="w", pady=(0, 20))
        
        self.category_combo.set(self.initial_data.get('category', ''))
        
        ctk.CTkLabel(content, text="Notes", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 5))
        self.notes_text = ctk.CTkTextbox(content, width=380, height=100, fg_color=COLOR_SURFACE, border_color="#333333", border_width=1)
        self.notes_text.pack(pady=(0, 25))
        self.notes_text.insert("1.0", self.initial_data.get('notes', ''))
        
        # Buttons
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(10, 0))
        
        ctk.CTkButton(
            btn_frame, text="Cancel", width=180, height=45,
            fg_color="transparent", border_width=1, border_color="#444444",
            command=self.destroy
        ).pack(side="left")
        
        ctk.CTkButton(
            btn_frame, text="Save Entry", width=180, height=45,
            fg_color=COLOR_ACCENT, text_color="black", font=ctk.CTkFont(weight="bold"),
            command=self._save
        ).pack(side="right")
    
    def _toggle_pass(self):
        self.pass_visible = not self.pass_visible
        self.password_entry.configure(show="" if self.pass_visible else "•")
        self.toggle_btn.configure(text="🔒" if self.pass_visible else "👁")

    def _generate_password(self):
        from generators.password_generator import PasswordGenerator, PasswordType, PasswordOptions
        gen = PasswordGenerator()
        password = gen.generate(PasswordType.STANDARD, PasswordOptions(length=20))
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
    
    def _save(self):
        title = self.title_entry.get().strip()
        password = self.password_entry.get()
        
        if not title or not password:
            return
        
        data = {
            'title': title,
            'username': self.username_entry.get().strip(),
            'password': password,
            'url': self.url_entry.get().strip(),
            'category': self.category_combo.get(),
            'notes': self.notes_text.get("1.0", "end").strip()
        }
        
        self.on_save(data)
        self.destroy()
=======
"""
Password vault frame for viewing and managing passwords.
"""
import customtkinter as ctk
from typing import Callable, List, Dict, Any, Optional

from utils.clipboard import ClipboardManager


class VaultFrame(ctk.CTkFrame):
    """Password vault with list and detail view."""
    
    def __init__(self, master, db_manager, on_refresh: Callable = None, **kwargs):
        super().__init__(master, **kwargs)
        
        self.db = db_manager
        self.on_refresh = on_refresh
        self.passwords: List[Dict[str, Any]] = []
        self.selected_id: Optional[int] = None
        
        self.configure(fg_color="transparent")
        
        # Split pane
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_list_panel()
        self._create_detail_panel()
    
    def _create_list_panel(self):
        """Create left panel with password list."""
        self.list_frame = ctk.CTkFrame(self)
        self.list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        # Header
        header = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=15)
        
        ctk.CTkLabel(
            header, text="🔐 Password Vault",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(side="left")
        
        self.add_btn = ctk.CTkButton(
            header, text="+", width=30, height=30,
            command=self._show_add_dialog
        )
        self.add_btn.pack(side="right")
        
        # Search
        self.search_entry = ctk.CTkEntry(
            self.list_frame, placeholder_text="🔍 Search...",
            height=35
        )
        self.search_entry.pack(fill="x", padx=10, pady=(0, 10))
        self.search_entry.bind("<KeyRelease>", self._on_search)
        
        # Scrollable list
        self.list_scroll = ctk.CTkScrollableFrame(self.list_frame)
        self.list_scroll.pack(fill="both", expand=True, padx=5, pady=5)
    
    def _create_detail_panel(self):
        """Create right panel with password details."""
        self.detail_frame = ctk.CTkFrame(self)
        self.detail_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        
        # Header
        self.detail_header = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.detail_header.pack(fill="x", padx=15, pady=15)
        
        self.detail_title = ctk.CTkLabel(
            self.detail_header, text="Select a password",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.detail_title.pack(side="left")
        
        # Action buttons (hidden initially)
        self.action_frame = ctk.CTkFrame(self.detail_header, fg_color="transparent")
        self.action_frame.pack(side="right")
        
        self.edit_btn = ctk.CTkButton(
            self.action_frame, text="Edit", width=60,
            command=self._edit_password
        )
        
        self.delete_btn = ctk.CTkButton(
            self.action_frame, text="Delete", width=60,
            fg_color="#e74c3c", hover_color="#c0392b",
            command=self._delete_password
        )
        
        # Content area
        self.detail_content = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.detail_content.pack(fill="both", expand=True, padx=15)
        
        # Empty state
        self.empty_label = ctk.CTkLabel(
            self.detail_content,
            text="Select a password from the list\nor add a new one",
            text_color="gray"
        )
        self.empty_label.pack(expand=True)
        
        # Detail fields (hidden initially)
        self.fields_frame = ctk.CTkFrame(self.detail_content, fg_color="transparent")
        
        self._create_field("username", "👤 Username")
        self._create_field("password", "🔑 Password", is_password=True)
        self._create_field("url", "🌐 URL")
        self._create_field("notes", "📝 Notes", is_textbox=True)
        self._create_field("category", "📁 Category")
    
    def _create_field(self, name: str, label: str, 
                      is_password: bool = False, is_textbox: bool = False):
        """Create a detail field."""
        frame = ctk.CTkFrame(self.fields_frame, fg_color="transparent")
        frame.pack(fill="x", pady=8)
        
        ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=12)).pack(anchor="w")
        
        field_row = ctk.CTkFrame(frame, fg_color="transparent")
        field_row.pack(fill="x")
        
        if is_textbox:
            widget = ctk.CTkTextbox(field_row, height=80, state="disabled")
            widget.pack(side="left", fill="x", expand=True)
        else:
            widget = ctk.CTkEntry(field_row, height=35, state="disabled")
            if is_password:
                widget.configure(show="•")
            widget.pack(side="left", fill="x", expand=True)
        
        # Copy button
        copy_btn = ctk.CTkButton(
            field_row, text="📋", width=35, height=35,
            command=lambda n=name: self._copy_field(n)
        )
        copy_btn.pack(side="right", padx=(5, 0))
        
        # Show/hide for password
        if is_password:
            self.show_pass_btn = ctk.CTkButton(
                field_row, text="👁", width=35, height=35,
                command=self._toggle_password_visibility
            )
            self.show_pass_btn.pack(side="right", padx=(5, 0))
            self.password_visible = False
        
        setattr(self, f"field_{name}", widget)
    
    def _toggle_password_visibility(self):
        """Toggle password field visibility."""
        self.password_visible = not self.password_visible
        self.field_password.configure(show="" if self.password_visible else "•")
        self.show_pass_btn.configure(text="🔒" if self.password_visible else "👁")
    
    def _copy_field(self, field_name: str):
        """Copy field value to clipboard."""
        widget = getattr(self, f"field_{field_name}", None)
        if widget:
            if isinstance(widget, ctk.CTkTextbox):
                value = widget.get("1.0", "end").strip()
            else:
                # Temporarily enable to get value
                widget.configure(state="normal")
                value = widget.get()
                widget.configure(state="disabled")
            
            if value:
                ClipboardManager.copy(value)
    
    def refresh(self):
        """Refresh password list."""
        self.passwords = self.db.get_all_passwords()
        self._update_list()
    
    def _update_list(self, filter_text: str = ""):
        """Update the password list display."""
        # Clear existing
        for widget in self.list_scroll.winfo_children():
            widget.destroy()
        
        # Filter
        passwords = self.passwords
        if filter_text:
            filter_lower = filter_text.lower()
            passwords = [
                p for p in passwords
                if filter_lower in p['title'].lower() or
                   filter_lower in (p['username'] or '').lower()
            ]
        
        # Create items
        for pwd in passwords:
            self._create_list_item(pwd)
        
        if not passwords:
            ctk.CTkLabel(
                self.list_scroll, text="No passwords found",
                text_color="gray"
            ).pack(pady=20)
    
    def _create_list_item(self, password: Dict[str, Any]):
        """Create a password list item."""
        item = ctk.CTkFrame(self.list_scroll, height=60, cursor="hand2")
        item.pack(fill="x", pady=2)
        item.pack_propagate(False)
        
        # Icon/emoji based on category
        icons = {
            "email": "📧", "bank": "🏦", "social": "👥",
            "work": "💼", "shopping": "🛒", "": "🔐"
        }
        category = (password.get('category') or '').lower()
        icon = icons.get(category, "🔐")
        
        content = ctk.CTkFrame(item, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=10, pady=8)
        
        ctk.CTkLabel(
            content, text=f"{icon} {password['title']}",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w"
        ).pack(fill="x")
        
        ctk.CTkLabel(
            content, text=password.get('username', ''),
            font=ctk.CTkFont(size=11),
            text_color="gray",
            anchor="w"
        ).pack(fill="x")
        
        # Bind click
        for widget in [item, content] + list(content.winfo_children()):
            widget.bind("<Button-1>", lambda e, p=password: self._select_password(p))
    
    def _select_password(self, password: Dict[str, Any]):
        """Select and display password details."""
        self.selected_id = password['id']
        
        # Update title
        self.detail_title.configure(text=password['title'])
        
        # Show action buttons
        self.edit_btn.pack(side="left", padx=2)
        self.delete_btn.pack(side="left", padx=2)
        
        # Hide empty state, show fields
        self.empty_label.pack_forget()
        self.fields_frame.pack(fill="both", expand=True)
        
        # Update fields
        self._update_field("username", password.get('username', ''))
        self._update_field("password", password.get('password', ''))
        self._update_field("url", password.get('url', ''))
        self._update_field("notes", password.get('notes', ''))
        self._update_field("category", password.get('category', ''))
        
        # Reset password visibility
        self.password_visible = False
        self.field_password.configure(show="•")
        self.show_pass_btn.configure(text="👁")
    
    def _update_field(self, name: str, value: str):
        """Update a field widget with a value."""
        widget = getattr(self, f"field_{name}", None)
        if widget:
            if isinstance(widget, ctk.CTkTextbox):
                widget.configure(state="normal")
                widget.delete("1.0", "end")
                widget.insert("1.0", value or "")
                widget.configure(state="disabled")
            else:
                widget.configure(state="normal")
                widget.delete(0, "end")
                widget.insert(0, value or "")
                widget.configure(state="disabled")
    
    def _on_search(self, event=None):
        """Handle search input."""
        query = self.search_entry.get()
        self._update_list(query)
    
    def _show_add_dialog(self):
        """Show dialog to add new password."""
        dialog = PasswordDialog(self, "Add Password", self._save_new_password)
        dialog.focus()
    
    def _edit_password(self):
        """Edit selected password."""
        if self.selected_id:
            password = self.db.get_password(self.selected_id)
            if password:
                dialog = PasswordDialog(
                    self, "Edit Password",
                    lambda data: self._save_edited_password(self.selected_id, data),
                    password
                )
                dialog.focus()
    
    def _save_new_password(self, data: Dict[str, str]):
        """Save a new password."""
        self.db.add_password(**data)
        self.refresh()
    
    def _save_edited_password(self, entry_id: int, data: Dict[str, str]):
        """Save edited password."""
        self.db.update_password(entry_id, **data)
        self.refresh()
        # Re-select to update details
        password = self.db.get_password(entry_id)
        if password:
            self._select_password(password)
    
    def _delete_password(self):
        """Delete selected password."""
        if self.selected_id:
            # Confirm dialog
            dialog = ctk.CTkInputDialog(
                text="Type 'DELETE' to confirm deletion:",
                title="Confirm Delete"
            )
            result = dialog.get_input()
            if result == "DELETE":
                self.db.delete_password(self.selected_id)
                self.selected_id = None
                self.refresh()
                # Reset detail view
                self.detail_title.configure(text="Select a password")
                self.edit_btn.pack_forget()
                self.delete_btn.pack_forget()
                self.fields_frame.pack_forget()
                self.empty_label.pack(expand=True)


class PasswordDialog(ctk.CTkToplevel):
    """Dialog for adding/editing passwords."""
    
    def __init__(self, parent, title: str, on_save: Callable,
                 initial_data: Dict[str, Any] = None):
        super().__init__(parent)
        
        self.on_save = on_save
        self.initial_data = initial_data or {}
        
        self.title(title)
        self.geometry("400x500")
        self.resizable(False, False)
        
        # Make modal
        self.transient(parent)
        self.grab_set()
        
        self._create_form()
    
    def _create_form(self):
        """Create the form fields."""
        content = ctk.CTkScrollableFrame(self)
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(content, text="Title *").pack(anchor="w", pady=(0, 5))
        self.title_entry = ctk.CTkEntry(content, width=360)
        self.title_entry.pack(pady=(0, 15))
        self.title_entry.insert(0, self.initial_data.get('title', ''))
        
        # Username
        ctk.CTkLabel(content, text="Username").pack(anchor="w", pady=(0, 5))
        self.username_entry = ctk.CTkEntry(content, width=360)
        self.username_entry.pack(pady=(0, 15))
        self.username_entry.insert(0, self.initial_data.get('username', ''))
        
        # Password
        ctk.CTkLabel(content, text="Password *").pack(anchor="w", pady=(0, 5))
        self.password_entry = ctk.CTkEntry(content, width=360, show="•")
        self.password_entry.pack(pady=(0, 5))
        self.password_entry.insert(0, self.initial_data.get('password', ''))
        
        # Generate button
        ctk.CTkButton(
            content, text="Generate Password", width=360,
            command=self._generate_password
        ).pack(pady=(0, 15))
        
        # URL
        ctk.CTkLabel(content, text="URL").pack(anchor="w", pady=(0, 5))
        self.url_entry = ctk.CTkEntry(content, width=360)
        self.url_entry.pack(pady=(0, 15))
        self.url_entry.insert(0, self.initial_data.get('url', ''))
        
        # Category
        ctk.CTkLabel(content, text="Category").pack(anchor="w", pady=(0, 5))
        self.category_combo = ctk.CTkComboBox(
            content, width=360,
            values=["", "Email", "Bank", "Social", "Work", "Shopping", "Other"]
        )
        self.category_combo.pack(pady=(0, 15))
        self.category_combo.set(self.initial_data.get('category', ''))
        
        # Notes
        ctk.CTkLabel(content, text="Notes").pack(anchor="w", pady=(0, 5))
        self.notes_text = ctk.CTkTextbox(content, width=360, height=80)
        self.notes_text.pack(pady=(0, 15))
        self.notes_text.insert("1.0", self.initial_data.get('notes', ''))
        
        # Buttons
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(10, 0))
        
        ctk.CTkButton(
            btn_frame, text="Cancel", width=170,
            fg_color="gray", command=self.destroy
        ).pack(side="left")
        
        ctk.CTkButton(
            btn_frame, text="Save", width=170,
            command=self._save
        ).pack(side="right")
    
    def _generate_password(self):
        """Generate a random password."""
        from generators.password_generator import PasswordGenerator, PasswordType, PasswordOptions
        gen = PasswordGenerator()
        password = gen.generate(PasswordType.STANDARD, PasswordOptions(length=20))
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
    
    def _save(self):
        """Save the password."""
        title = self.title_entry.get().strip()
        password = self.password_entry.get()
        
        if not title:
            return
        if not password:
            return
        
        data = {
            'title': title,
            'username': self.username_entry.get().strip(),
            'password': password,
            'url': self.url_entry.get().strip(),
            'category': self.category_combo.get(),
            'notes': self.notes_text.get("1.0", "end").strip()
        }
        
        self.on_save(data)
        self.destroy()
>>>>>>> 6b91baecfa0930c653d444e61194cb7690e1fceb
