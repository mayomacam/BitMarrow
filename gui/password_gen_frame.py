<<<<<<< HEAD
"""
Password generator frame with all generation options.
"""
import customtkinter as ctk
from typing import Callable

from generators.password_generator import (
    PasswordGenerator, PasswordType, PasswordOptions
)
from gui.components.strength_meter import StrengthMeter
from utils.clipboard import ClipboardManager


from config import COLOR_BG, COLOR_SURFACE, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM

class PasswordGenFrame(ctk.CTkFrame):
    """Modern password generator with premium interface."""
    
    def __init__(self, master, db_manager=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        self.db = db_manager
        self.generator = PasswordGenerator()
        
        # Split pane
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_options_panel()
        self._create_preview_panel()
        
        self._generate()
    
    def _create_options_panel(self):
        """Create left panel with generation options."""
        self.options_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.options_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # Header
        ctk.CTkLabel(
            self.options_frame, text="Generation Settings",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(padx=20, pady=(25, 20), anchor="w")
        
        content = ctk.CTkScrollableFrame(self.options_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Password Type
        ctk.CTkLabel(content, text="Complexity Level", font=ctk.CTkFont(weight="bold", size=13), text_color=COLOR_TEXT_DIM).pack(anchor="w", pady=(0, 5))
        self.type_var = ctk.StringVar(value="standard")
        self.type_combo = ctk.CTkComboBox(
            content, variable=self.type_var,
            values=["standard", "passphrase", "pin", "memorable", "hex"],
            fg_color=COLOR_BG, border_color="#333333", height=40,
            command=self._on_type_change
        )
        self.type_combo.pack(fill="x", pady=(0, 20))
        
        # Length
        len_header = ctk.CTkFrame(content, fg_color="transparent")
        len_header.pack(fill="x", pady=(0, 5))
        ctk.CTkLabel(len_header, text="Character Length", font=ctk.CTkFont(weight="bold", size=13), text_color=COLOR_TEXT_DIM).pack(side="left")
        self.length_label = ctk.CTkLabel(len_header, text="16", font=ctk.CTkFont(weight="bold", size=14), text_color=COLOR_ACCENT)
        self.length_label.pack(side="right")
        
        self.length_var = ctk.IntVar(value=16)
        self.length_slider = ctk.CTkSlider(
            content, from_=4, to=128,
            variable=self.length_var,
            button_color=COLOR_ACCENT, button_hover_color="#2ecc71",
            command=self._on_length_change
        )
        self.length_slider.pack(fill="x", pady=(0, 25))
        
        # Character Options
        self.char_options_frame = ctk.CTkFrame(content, fg_color="transparent")
        self.char_options_frame.pack(fill="x")
        
        ctk.CTkLabel(
            self.char_options_frame, text="Security Characters",
            font=ctk.CTkFont(weight="bold", size=13), text_color=COLOR_TEXT_DIM
        ).pack(anchor="w", pady=(0, 10))
        
        def add_check(label, var_name):
            var = ctk.BooleanVar(value=True)
            cb = ctk.CTkCheckBox(
                self.char_options_frame, text=label,
                variable=var, command=self._generate,
                border_color="#444444", hover_color="#333333",
                fg_color=COLOR_ACCENT
            )
            cb.pack(anchor="w", pady=6)
            setattr(self, var_name, var)

        add_check("Include Uppercase (A-Z)", "uppercase_var")
        add_check("Include Lowercase (a-z)", "lowercase_var")
        add_check("Include Numbers (0-9)", "numbers_var")
        add_check("Include Symbols (!@#$%)", "symbols_var")
        
        self.brackets_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            self.char_options_frame, text="Include Brackets ([{}])",
            variable=self.brackets_var, command=self._generate,
            border_color="#444444", checkmark_color="black", fg_color=COLOR_ACCENT
        ).pack(anchor="w", pady=6)
        
        # Advanced
        ctk.CTkLabel(content, text="Formatting", font=ctk.CTkFont(weight="bold", size=13), text_color=COLOR_TEXT_DIM).pack(anchor="w", pady=(15, 10))
        
        self.similar_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            content, text="Avoid ambiguous characters",
            variable=self.similar_var, command=self._generate,
            border_color="#444444", checkmark_color="black", fg_color=COLOR_ACCENT
        ).pack(anchor="w", pady=6)
        
        self.start_letter_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            content, text="Force start with letter",
            variable=self.start_letter_var, command=self._generate,
            border_color="#444444", checkmark_color="black", fg_color=COLOR_ACCENT
        ).pack(anchor="w", pady=6)
    
    def _create_preview_panel(self):
        """Create right panel with password preview."""
        self.preview_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.preview_frame.grid(row=0, column=1, sticky="nsew")
        
        content = ctk.CTkFrame(self.preview_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Header
        ctk.CTkLabel(
            content, text="Result",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(0, 20))
        
        # Password display
        self.password_frame = ctk.CTkFrame(content, height=120, fg_color=COLOR_BG, corner_radius=15, border_width=1, border_color="#333333")
        self.password_frame.pack(fill="x", pady=(0, 25))
        self.password_frame.pack_propagate(False)
        
        self.password_label = ctk.CTkLabel(
            self.password_frame,
            text="",
            font=ctk.CTkFont(family="Consolas", size=24, weight="bold"),
            text_color=COLOR_ACCENT,
            wraplength=350,
            justify="center"
        )
        self.password_label.pack(expand=True, padx=20)
        
        # Strength meter
        ctk.CTkLabel(content, text="Security Strength Analysis", font=ctk.CTkFont(weight="bold", size=13), text_color=COLOR_TEXT_DIM).pack(anchor="w", pady=(0, 10))
        self.strength_meter = StrengthMeter(content)
        self.strength_meter.pack(fill="x", pady=(0, 30))
        
        # Action buttons
        btn_grid = ctk.CTkFrame(content, fg_color="transparent")
        btn_grid.pack(fill="x", pady=(0, 30))
        
        self.regenerate_btn = ctk.CTkButton(
            btn_grid, text="Regenerate",
            height=45, fg_color="transparent", border_width=1, border_color=COLOR_ACCENT,
            text_color=COLOR_ACCENT, hover_color="#222222",
            font=ctk.CTkFont(weight="bold"),
            command=self._generate
        )
        self.regenerate_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.copy_btn = ctk.CTkButton(
            btn_grid, text="Copy Result",
            height=45, fg_color=COLOR_ACCENT, text_color="black",
            font=ctk.CTkFont(weight="bold"),
            command=self._copy_password
        )
        self.copy_btn.pack(side="left", fill="x", expand=True)

        self.save_btn = ctk.CTkButton(
            content, text="Save to Vault",
            height=45, fg_color="#3498db", hover_color="#2980b9",
            font=ctk.CTkFont(weight="bold"),
            command=self._save_to_vault
        )
        self.save_btn.pack(fill="x", pady=(0, 20))
        
        # Smart Suggestions
        ctk.CTkLabel(
            content, text="Smart Suggestions",
            font=ctk.CTkFont(size=14, weight="bold"), text_color=COLOR_TEXT_DIM
        ).pack(anchor="w", pady=(10, 10))
        
        self.suggestions_frame = ctk.CTkFrame(content, fg_color="transparent")
        self.suggestions_frame.pack(fill="x", pady=(0, 20))
        
        # History
        ctk.CTkLabel(
            content, text="Previous Attempts",
            font=ctk.CTkFont(size=14, weight="bold"), text_color=COLOR_TEXT_DIM
        ).pack(anchor="w", pady=(10, 10))
        
        self.history_frame = ctk.CTkScrollableFrame(content, height=180, fg_color=COLOR_BG, corner_radius=12)
        self.history_frame.pack(fill="both")
        
        self.history: list = []
    
    def _on_type_change(self, value):
        if value == "standard":
            self.char_options_frame.pack(fill="x")
        else:
            self.char_options_frame.pack_forget()
        self._generate()
    
    def _on_length_change(self, value):
        self.length_label.configure(text=str(int(value)))
        self._generate()
    
    def _generate(self, *args):
        password_type = PasswordType(self.type_var.get())
        options = PasswordOptions(
            length=self.length_var.get(),
            use_uppercase=self.uppercase_var.get(),
            use_lowercase=self.lowercase_var.get(),
            use_numbers=self.numbers_var.get(),
            use_symbols=self.symbols_var.get(),
            use_brackets=self.brackets_var.get(),
            similar_randomization=self.similar_var.get(),
            start_with_letter=self.start_letter_var.get()
        )
        
        password = self.generator.generate(password_type, options)
        self.current_password = password
        self.password_label.configure(text=password)
        
        strength = PasswordGenerator.calculate_strength(password)
        self.strength_meter.update_strength(strength['score'], strength['strength'])
        
        self._update_suggestions(password_type, options)
        self._add_to_history(password)
    
    def _update_suggestions(self, password_type, options):
        """Update the suggestions list."""
        for widget in self.suggestions_frame.winfo_children():
            widget.destroy()
            
        suggestions = self.generator.suggest(password_type, options, count=3)
        
        for suggestion in suggestions:
            btn = ctk.CTkButton(
                self.suggestions_frame, text=suggestion,
                height=35, fg_color=COLOR_BG, border_width=1, border_color="#333333",
                text_color=COLOR_TEXT, hover_color="#333333",
                font=ctk.CTkFont(family="Consolas", size=12),
                command=lambda s=suggestion: self._select_suggestion(s)
            )
            btn.pack(fill="x", pady=4)

    def _select_suggestion(self, suggestion):
        """Select a suggestion as the main password."""
        self.current_password = suggestion
        self.password_label.configure(text=suggestion)
        strength = PasswordGenerator.calculate_strength(suggestion)
        self.strength_meter.update_strength(strength['score'], strength['strength'])
        self._add_to_history(suggestion)

    def _add_to_history(self, password: str):
        if password in self.history: return
        
        self.history.insert(0, password)
        self.history = self.history[:10]
        
        for widget in self.history_frame.winfo_children(): widget.destroy()
        
        for pwd in self.history:
            item = ctk.CTkFrame(self.history_frame, height=45, fg_color="transparent")
            item.pack(fill="x", pady=2, padx=5)
            item.pack_propagate(False)
            
            display = pwd[:25] + "..." if len(pwd) > 25 else pwd
            ctk.CTkLabel(item, text=display, font=ctk.CTkFont(family="Consolas", size=12)).pack(side="left", padx=10)
            
            ctk.CTkButton(
                item, text="📋", width=30, height=30, fg_color="transparent", hover_color="#333333",
                command=lambda p=pwd: ClipboardManager.copy(p)
            ).pack(side="right", padx=5)
    
    def _copy_password(self):
        if hasattr(self, 'current_password'):
            ClipboardManager.copy(self.current_password)
            self.copy_btn.configure(text="Result Copied!")
            self.after(2000, lambda: self.copy_btn.configure(text="Copy Result"))
    
    def _save_to_vault(self):
        if not hasattr(self, 'current_password') or not self.db: return
        from gui.vault_frame import PasswordDialog
        dialog = PasswordDialog(self, "Save to Vault", self._do_save, {'password': self.current_password})
        dialog.focus()
    
    def _do_save(self, data):
        if self.db: self.db.add_password(**data)
=======
"""
Password generator frame with all generation options.
"""
import customtkinter as ctk
from typing import Callable

from generators.password_generator import (
    PasswordGenerator, PasswordType, PasswordOptions
)
from gui.components.strength_meter import StrengthMeter
from utils.clipboard import ClipboardManager


class PasswordGenFrame(ctk.CTkFrame):
    """Password generator interface."""
    
    def __init__(self, master, db_manager=None, **kwargs):
        super().__init__(master, **kwargs)
        
        self.db = db_manager
        self.generator = PasswordGenerator()
        
        self.configure(fg_color="transparent")
        
        # Split pane
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)
        
        self._create_options_panel()
        self._create_preview_panel()
        
        # Generate initial password
        self._generate()
    
    def _create_options_panel(self):
        """Create left panel with generation options."""
        self.options_frame = ctk.CTkFrame(self)
        self.options_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        # Header
        ctk.CTkLabel(
            self.options_frame, text="⚡ Generator Options",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(padx=15, pady=15, anchor="w")
        
        content = ctk.CTkScrollableFrame(self.options_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Password Type
        ctk.CTkLabel(content, text="Password Type").pack(anchor="w", pady=(0, 5))
        self.type_var = ctk.StringVar(value="standard")
        self.type_combo = ctk.CTkComboBox(
            content, variable=self.type_var,
            values=["standard", "passphrase", "pin", "memorable", "hex"],
            command=self._on_type_change
        )
        self.type_combo.pack(fill="x", pady=(0, 15))
        
        # Length
        ctk.CTkLabel(content, text="Length").pack(anchor="w", pady=(0, 5))
        
        length_frame = ctk.CTkFrame(content, fg_color="transparent")
        length_frame.pack(fill="x", pady=(0, 15))
        
        self.length_var = ctk.IntVar(value=16)
        self.length_slider = ctk.CTkSlider(
            length_frame, from_=8, to=64,
            variable=self.length_var,
            command=self._on_length_change
        )
        self.length_slider.pack(side="left", fill="x", expand=True)
        
        self.length_label = ctk.CTkLabel(length_frame, text="16", width=40)
        self.length_label.pack(side="right")
        
        # Character Options (for standard mode)
        self.char_options_frame = ctk.CTkFrame(content, fg_color="transparent")
        self.char_options_frame.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(
            self.char_options_frame, text="Character Sets"
        ).pack(anchor="w", pady=(0, 10))
        
        self.uppercase_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            self.char_options_frame, text="Uppercase (A-Z)",
            variable=self.uppercase_var, command=self._generate
        ).pack(anchor="w", pady=2)
        
        self.lowercase_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            self.char_options_frame, text="Lowercase (a-z)",
            variable=self.lowercase_var, command=self._generate
        ).pack(anchor="w", pady=2)
        
        self.numbers_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            self.char_options_frame, text="Numbers (0-9)",
            variable=self.numbers_var, command=self._generate
        ).pack(anchor="w", pady=2)
        
        self.symbols_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            self.char_options_frame, text="Symbols (!@#$%...)",
            variable=self.symbols_var, command=self._generate
        ).pack(anchor="w", pady=2)
        
        self.brackets_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            self.char_options_frame, text="Brackets ([]{})",
            variable=self.brackets_var, command=self._generate
        ).pack(anchor="w", pady=2)
        
        # Advanced Options
        ctk.CTkLabel(content, text="Advanced Options").pack(anchor="w", pady=(10, 10))
        
        self.similar_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            content, text="Similar char randomization",
            variable=self.similar_var, command=self._generate
        ).pack(anchor="w", pady=2)
        
        self.start_letter_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            content, text="Start with letter",
            variable=self.start_letter_var, command=self._generate
        ).pack(anchor="w", pady=2)
    
    def _create_preview_panel(self):
        """Create right panel with password preview."""
        self.preview_frame = ctk.CTkFrame(self)
        self.preview_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        
        # Header
        ctk.CTkLabel(
            self.preview_frame, text="🔑 Generated Password",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(padx=15, pady=15, anchor="w")
        
        content = ctk.CTkFrame(self.preview_frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Password display
        self.password_frame = ctk.CTkFrame(content, height=80)
        self.password_frame.pack(fill="x", pady=(0, 15))
        self.password_frame.pack_propagate(False)
        
        self.password_label = ctk.CTkLabel(
            self.password_frame,
            text="",
            font=ctk.CTkFont(family="Consolas", size=18),
            wraplength=350
        )
        self.password_label.pack(expand=True, padx=15)
        
        # Strength meter
        ctk.CTkLabel(content, text="Strength").pack(anchor="w", pady=(0, 5))
        self.strength_meter = StrengthMeter(content)
        self.strength_meter.pack(fill="x", pady=(0, 20))
        
        # Action buttons
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(0, 15))
        
        self.regenerate_btn = ctk.CTkButton(
            btn_frame, text="🔄 Regenerate",
            command=self._generate
        )
        self.regenerate_btn.pack(side="left", padx=(0, 10))
        
        self.copy_btn = ctk.CTkButton(
            btn_frame, text="📋 Copy",
            command=self._copy_password
        )
        self.copy_btn.pack(side="left", padx=(0, 10))
        
        self.save_btn = ctk.CTkButton(
            btn_frame, text="💾 Save to Vault",
            command=self._save_to_vault
        )
        self.save_btn.pack(side="left")
        
        # History
        ctk.CTkLabel(
            content, text="Recent Generations",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", pady=(20, 10))
        
        self.history_frame = ctk.CTkScrollableFrame(content, height=150)
        self.history_frame.pack(fill="x")
        
        self.history: list = []
    
    def _on_type_change(self, value):
        """Handle password type change."""
        # Show/hide character options based on type
        if value == "standard":
            self.char_options_frame.pack(fill="x", pady=(0, 15))
        else:
            self.char_options_frame.pack_forget()
        
        self._generate()
    
    def _on_length_change(self, value):
        """Handle length slider change."""
        self.length_label.configure(text=str(int(value)))
        self._generate()
    
    def _generate(self, *args):
        """Generate a new password."""
        password_type = PasswordType(self.type_var.get())
        
        options = PasswordOptions(
            length=self.length_var.get(),
            use_uppercase=self.uppercase_var.get(),
            use_lowercase=self.lowercase_var.get(),
            use_numbers=self.numbers_var.get(),
            use_symbols=self.symbols_var.get(),
            use_brackets=self.brackets_var.get(),
            similar_randomization=self.similar_var.get(),
            start_with_letter=self.start_letter_var.get()
        )
        
        password = self.generator.generate(password_type, options)
        self.current_password = password
        
        # Update display
        self.password_label.configure(text=password)
        
        # Update strength
        strength = PasswordGenerator.calculate_strength(password)
        self.strength_meter.update_strength(strength['score'], strength['strength'])
        
        # Add to history
        self._add_to_history(password)
    
    def _add_to_history(self, password: str):
        """Add password to history."""
        if password in self.history:
            return
        
        self.history.insert(0, password)
        self.history = self.history[:5]  # Keep last 5
        
        # Update history display
        for widget in self.history_frame.winfo_children():
            widget.destroy()
        
        for pwd in self.history:
            item = ctk.CTkFrame(self.history_frame, height=35)
            item.pack(fill="x", pady=2)
            item.pack_propagate(False)
            
            # Truncate display
            display = pwd[:30] + "..." if len(pwd) > 30 else pwd
            
            ctk.CTkLabel(
                item, text=display,
                font=ctk.CTkFont(family="Consolas", size=11)
            ).pack(side="left", padx=10, pady=5)
            
            ctk.CTkButton(
                item, text="📋", width=30,
                command=lambda p=pwd: ClipboardManager.copy(p)
            ).pack(side="right", padx=5)
    
    def _copy_password(self):
        """Copy current password to clipboard."""
        if hasattr(self, 'current_password'):
            ClipboardManager.copy(self.current_password)
            self.copy_btn.configure(text="✓ Copied!")
            self.after(2000, lambda: self.copy_btn.configure(text="📋 Copy"))
    
    def _save_to_vault(self):
        """Save generated password to vault."""
        if not hasattr(self, 'current_password') or not self.db:
            return
        
        from gui.vault_frame import PasswordDialog
        dialog = PasswordDialog(
            self, "Save Password",
            self._do_save,
            {'password': self.current_password}
        )
        dialog.focus()
    
    def _do_save(self, data):
        """Actually save to database."""
        if self.db:
            self.db.add_password(**data)
>>>>>>> 6b91baecfa0930c653d444e61194cb7690e1fceb
