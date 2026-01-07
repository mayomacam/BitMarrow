import customtkinter as ctk
from typing import Callable, Dict
from config import COLOR_SIDEBAR, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM

class Sidebar(ctk.CTkFrame):
    """Custom sidebar navigation component."""
    
    def __init__(self, master, on_change: Callable[[str], None], **kwargs):
        super().__init__(master, fg_color=COLOR_SIDEBAR, width=200, corner_radius=0, **kwargs)
        
        self.on_change = on_change
        self.buttons: Dict[str, ctk.CTkButton] = {}
        self.active_button = None
        
        self.grid_rowconfigure(0, weight=0) # Logo area
        self.grid_rowconfigure(1, weight=1) # Navigation area
        self.grid_rowconfigure(2, weight=0) # Bottom area
        
        self._create_widgets()
        
    def _create_widgets(self):
        # Logo / Title
        logo_label = ctk.CTkLabel(
            self, text="🔐 BitMarrow",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=COLOR_ACCENT
        )
        logo_label.grid(row=0, column=0, padx=20, pady=30)
        
        # Navigation Buttons
        nav_container = ctk.CTkFrame(self, fg_color="transparent")
        nav_container.grid(row=1, column=0, sticky="nsew", padx=10)
        
        items = [
            ("🔐 Passwords", "passwords"),
            ("⚡ Pass Gen", "pass_gen"),
            ("🔑 Key Gen", "key_gen"),
            ("📜 Key Vault", "key_vault"),
            ("📝 Notes", "notes"),
            ("📊 Stats", "stats"),
            ("⚙️ Settings", "settings")
        ]
        
        for i, (label, key) in enumerate(items):
            btn = ctk.CTkButton(
                nav_container,
                text=label,
                text_color=COLOR_TEXT,
                fg_color="transparent",
                hover_color=COLOR_ACCENT,
                anchor="w",
                height=40,
                corner_radius=8,
                command=lambda k=key: self._handle_click(k)
            )
            btn.pack(fill="x", pady=5)
            self.buttons[key] = btn
            
        # Bottom spacer or additional items
        self.bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.bottom_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=20)
        
    def _handle_click(self, key: str):
        self.set_active(key)
        self.on_change(key)
        
    def set_active(self, key: str):
        """Highlight the active button."""
        if self.active_button:
            self.active_button.configure(fg_color="transparent", text_color=COLOR_TEXT)
            
        if key in self.buttons:
            self.active_button = self.buttons[key]
            self.active_button.configure(fg_color=COLOR_ACCENT, text_color="black") # High contrast for active
