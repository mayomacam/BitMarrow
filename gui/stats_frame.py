<<<<<<< HEAD
"""
Statistics frame for password vault analytics.
"""
import customtkinter as ctk
from typing import Dict, Any


from config import COLOR_BG, COLOR_SURFACE, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM

class StatsFrame(ctk.CTkFrame):
    """Statistics and analytics for password vault with modern UI."""
    
    def __init__(self, master, db_manager=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        self.db = db_manager
        
        # Main content
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        self._create_overview()
        self._create_details()
    
    def _create_overview(self):
        """Create premium overview cards."""
        overview = ctk.CTkFrame(self, fg_color="transparent")
        overview.grid(row=0, column=0, columnspan=2, sticky="ew", padx=20, pady=(0, 20))
        
        # Stats cards row
        cards = ctk.CTkFrame(overview, fg_color="transparent")
        cards.pack(fill="x")
        
        self.total_card = self._create_stat_card(cards, "🔐", "Total Passwords", "0", COLOR_ACCENT)
        self.total_card.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.keys_card = self._create_stat_card(cards, "🔑", "Secured Keys", "0", "#9b59b6")
        self.keys_card.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.weak_card = self._create_stat_card(cards, "⚠️", "Security Risks", "0", "#e74c3c")
        self.weak_card.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.strong_card = self._create_stat_card(cards, "🛡️", "Strong Entries", "0", "#2ecc71")
        self.strong_card.pack(side="left", fill="x", expand=True)
    
    def _create_stat_card(self, parent, icon: str, title: str, 
                          value: str, color: str) -> ctk.CTkFrame:
        """Create a premium statistics card."""
        card = ctk.CTkFrame(parent, height=120, fg_color=COLOR_SURFACE, corner_radius=15)
        card.pack_propagate(False)
        
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(expand=True, padx=20, pady=15)
        
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text=icon, font=ctk.CTkFont(size=24)).pack(side="left")
        ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=12, weight="bold"), text_color=COLOR_TEXT_DIM).pack(side="left", padx=(10, 0))
        
        value_label = ctk.CTkLabel(content, text=value, font=ctk.CTkFont(size=36, weight="bold"), text_color=color)
        value_label.pack(anchor="w", pady=(5, 0))
        
        card.value_label = value_label
        return card
    
    def _create_details(self):
        """Create detailed statistics panels."""
        # Categories
        self.categories_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.categories_frame.grid(row=1, column=0, sticky="nsew", padx=(20, 10), pady=(0, 20))
        
        ctk.CTkLabel(self.categories_frame, text="By Category", font=ctk.CTkFont(size=16, weight="bold")).pack(padx=20, pady=20, anchor="w")
        
        self.categories_content = ctk.CTkScrollableFrame(self.categories_frame, fg_color="transparent")
        self.categories_content.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Strength
        self.strength_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.strength_frame.grid(row=1, column=1, sticky="nsew", padx=(10, 20), pady=(0, 20))
        
        ctk.CTkLabel(self.strength_frame, text="Security Audit", font=ctk.CTkFont(size=16, weight="bold")).pack(padx=20, pady=20, anchor="w")
        
        self.strength_content = ctk.CTkScrollableFrame(self.strength_frame, fg_color="transparent")
        self.strength_content.pack(fill="both", expand=True, padx=20, pady=(0, 20))
    
    def refresh(self):
        if not self.db: return
        
        stats = self.db.get_password_stats()
        passwords = self.db.get_all_passwords()
        
        total = stats['total']
        weak = stats['weak_count']
        strong = total - weak
        
        self.total_card.value_label.configure(text=str(total))
        self.keys_card.value_label.configure(text=str(stats['key_count']))
        self.weak_card.value_label.configure(text=str(weak))
        self.strong_card.value_label.configure(text=str(strong))
        
        for widget in self.categories_content.winfo_children(): widget.destroy()
        
        categories = stats.get('categories', {})
        if categories:
            for category, count in sorted(categories.items(), key=lambda x: -x[1]):
                self._create_category_bar(category or "Uncategorized", count, total)
        else:
            ctk.CTkLabel(self.categories_content, text="No data available", text_color=COLOR_TEXT_DIM).pack(pady=40)
        
        for widget in self.strength_content.winfo_children(): widget.destroy()
        
        if passwords:
            from generators.password_generator import PasswordGenerator
            strength_counts = {"Weak": 0, "Fair": 0, "Good": 0, "Strong": 0, "Excellent": 0}
            for p in passwords:
                result = PasswordGenerator.calculate_strength(p['password'])
                strength_counts[result['strength']] = strength_counts.get(result['strength'], 0) + 1
            
            colors = {
                "Weak": "#e74c3c", 
                "Fair": "#f39c12", 
                "Good": "#3498db", 
                "Strong": "#2ecc71",
                "Excellent": COLOR_ACCENT
            }
            for strength, count in strength_counts.items():
                if count > 0: self._create_strength_bar(strength, count, total, colors[strength])
        else:
            ctk.CTkLabel(self.strength_content, text="No passwords found", text_color=COLOR_TEXT_DIM).pack(pady=40)
    
    def _create_category_bar(self, category: str, count: int, total: int):
        frame = ctk.CTkFrame(self.categories_content, fg_color="transparent")
        frame.pack(fill="x", pady=8)
        
        label_frame = ctk.CTkFrame(frame, fg_color="transparent")
        label_frame.pack(fill="x")
        
        ctk.CTkLabel(label_frame, text=category, font=ctk.CTkFont(size=13)).pack(side="left")
        ctk.CTkLabel(label_frame, text=str(count), font=ctk.CTkFont(weight="bold"), text_color=COLOR_ACCENT).pack(side="right")
        
        bar = ctk.CTkProgressBar(frame, height=8, progress_color=COLOR_ACCENT, fg_color=COLOR_BG)
        bar.pack(fill="x", pady=(5, 0))
        bar.set(count / max(total, 1))
    
    def _create_strength_bar(self, strength: str, count: int, total: int, color: str):
        frame = ctk.CTkFrame(self.strength_content, fg_color="transparent")
        frame.pack(fill="x", pady=8)
        
        label_frame = ctk.CTkFrame(frame, fg_color="transparent")
        label_frame.pack(fill="x")
        
        ctk.CTkLabel(label_frame, text=strength, text_color=color, font=ctk.CTkFont(weight="bold", size=13)).pack(side="left")
        pct = int(count / max(total, 1) * 100)
        ctk.CTkLabel(label_frame, text=f"{count} ({pct}%)", text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=12)).pack(side="right")
        
        bar = ctk.CTkProgressBar(frame, height=8, progress_color=color, fg_color=COLOR_BG)
        bar.pack(fill="x", pady=(5, 0))
        bar.set(count / max(total, 1))
=======
"""
Statistics frame for password vault analytics.
"""
import customtkinter as ctk
from typing import Dict, Any


class StatsFrame(ctk.CTkFrame):
    """Statistics and analytics for password vault."""
    
    def __init__(self, master, db_manager=None, **kwargs):
        super().__init__(master, **kwargs)
        
        self.db = db_manager
        
        self.configure(fg_color="transparent")
        
        # Main content
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        self._create_overview()
        self._create_details()
    
    def _create_overview(self):
        """Create overview cards."""
        overview = ctk.CTkFrame(self, fg_color="transparent")
        overview.grid(row=0, column=0, columnspan=2, sticky="ew", padx=15, pady=15)
        
        # Title
        ctk.CTkLabel(
            overview, text="📊 Vault Statistics",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(0, 20))
        
        # Stats cards row
        cards = ctk.CTkFrame(overview, fg_color="transparent")
        cards.pack(fill="x")
        
        # Total passwords card
        self.total_card = self._create_stat_card(
            cards, "🔐", "Total Passwords", "0", "#3498db"
        )
        self.total_card.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Total keys card
        self.keys_card = self._create_stat_card(
            cards, "🔑", "Crypto Keys", "0", "#9b59b6"
        )
        self.keys_card.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Weak passwords card
        self.weak_card = self._create_stat_card(
            cards, "⚠️", "Weak Passwords", "0", "#e74c3c"
        )
        self.weak_card.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Strong passwords card
        self.strong_card = self._create_stat_card(
            cards, "✅", "Strong Passwords", "0", "#2ecc71"
        )
        self.strong_card.pack(side="left", fill="x", expand=True)
    
    def _create_stat_card(self, parent, icon: str, title: str, 
                          value: str, color: str) -> ctk.CTkFrame:
        """Create a statistics card."""
        card = ctk.CTkFrame(parent, height=100)
        card.pack_propagate(False)
        
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(expand=True, padx=15, pady=10)
        
        # Icon and title
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x")
        
        ctk.CTkLabel(
            header, text=icon,
            font=ctk.CTkFont(size=24)
        ).pack(side="left")
        
        ctk.CTkLabel(
            header, text=title,
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(side="left", padx=(10, 0))
        
        # Value
        value_label = ctk.CTkLabel(
            content, text=value,
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=color
        )
        value_label.pack(anchor="w", pady=(5, 0))
        
        # Store reference to value label
        card.value_label = value_label
        
        return card
    
    def _create_details(self):
        """Create detailed statistics panels."""
        # Categories breakdown
        self.categories_frame = ctk.CTkFrame(self)
        self.categories_frame.grid(row=1, column=0, sticky="nsew", padx=(15, 7), pady=(0, 15))
        
        ctk.CTkLabel(
            self.categories_frame, text="📁 By Category",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(padx=15, pady=15, anchor="w")
        
        self.categories_content = ctk.CTkScrollableFrame(
            self.categories_frame, fg_color="transparent"
        )
        self.categories_content.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Strength distribution
        self.strength_frame = ctk.CTkFrame(self)
        self.strength_frame.grid(row=1, column=1, sticky="nsew", padx=(7, 15), pady=(0, 15))
        
        ctk.CTkLabel(
            self.strength_frame, text="💪 Password Strength",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(padx=15, pady=15, anchor="w")
        
        self.strength_content = ctk.CTkScrollableFrame(
            self.strength_frame, fg_color="transparent"
        )
        self.strength_content.pack(fill="both", expand=True, padx=15, pady=(0, 15))
    
    def refresh(self):
        """Refresh statistics."""
        if not self.db:
            return
        
        stats = self.db.get_password_stats()
        passwords = self.db.get_all_passwords()
        
        # Update overview cards
        total = stats['total']
        weak = stats['weak_count']
        strong = total - weak
        
        self.total_card.value_label.configure(text=str(total))
        self.keys_card.value_label.configure(text=str(stats['key_count']))
        self.weak_card.value_label.configure(text=str(weak))
        self.strong_card.value_label.configure(text=str(strong))
        
        # Update categories
        for widget in self.categories_content.winfo_children():
            widget.destroy()
        
        categories = stats.get('categories', {})
        if categories:
            for category, count in sorted(categories.items(), key=lambda x: -x[1]):
                self._create_category_bar(category, count, total)
        else:
            ctk.CTkLabel(
                self.categories_content, text="No passwords yet",
                text_color="gray"
            ).pack(pady=20)
        
        # Update strength distribution
        for widget in self.strength_content.winfo_children():
            widget.destroy()
        
        if passwords:
            from generators.password_generator import PasswordGenerator
            
            strength_counts = {"Weak": 0, "Fair": 0, "Good": 0, "Strong": 0}
            for p in passwords:
                result = PasswordGenerator.calculate_strength(p['password'])
                strength_counts[result['strength']] = strength_counts.get(result['strength'], 0) + 1
            
            colors = {"Weak": "#e74c3c", "Fair": "#f39c12", "Good": "#3498db", "Strong": "#2ecc71"}
            
            for strength, count in strength_counts.items():
                if count > 0:
                    self._create_strength_bar(strength, count, total, colors[strength])
        else:
            ctk.CTkLabel(
                self.strength_content, text="No passwords yet",
                text_color="gray"
            ).pack(pady=20)
    
    def _create_category_bar(self, category: str, count: int, total: int):
        """Create a category bar chart item."""
        frame = ctk.CTkFrame(self.categories_content, fg_color="transparent")
        frame.pack(fill="x", pady=5)
        
        # Label
        label_frame = ctk.CTkFrame(frame, fg_color="transparent")
        label_frame.pack(fill="x")
        
        ctk.CTkLabel(label_frame, text=category).pack(side="left")
        ctk.CTkLabel(label_frame, text=str(count), text_color="gray").pack(side="right")
        
        # Bar
        bar = ctk.CTkProgressBar(frame, height=10)
        bar.pack(fill="x", pady=(5, 0))
        bar.set(count / max(total, 1))
    
    def _create_strength_bar(self, strength: str, count: int, total: int, color: str):
        """Create a strength bar chart item."""
        frame = ctk.CTkFrame(self.strength_content, fg_color="transparent")
        frame.pack(fill="x", pady=5)
        
        # Label
        label_frame = ctk.CTkFrame(frame, fg_color="transparent")
        label_frame.pack(fill="x")
        
        ctk.CTkLabel(label_frame, text=strength, text_color=color).pack(side="left")
        pct = int(count / max(total, 1) * 100)
        ctk.CTkLabel(label_frame, text=f"{count} ({pct}%)", text_color="gray").pack(side="right")
        
        # Bar
        bar = ctk.CTkProgressBar(frame, height=10, progress_color=color)
        bar.pack(fill="x", pady=(5, 0))
        bar.set(count / max(total, 1))
>>>>>>> 6b91baecfa0930c653d444e61194cb7690e1fceb
