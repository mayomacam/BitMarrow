<<<<<<< HEAD
"""
Password strength meter widget.
"""
import customtkinter as ctk


class StrengthMeter(ctk.CTkFrame):
    """Visual password strength indicator."""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        self.configure(fg_color="transparent")
        self.current_score = 0
        
        # Strength bar
        self.bar_frame = ctk.CTkFrame(self, height=8, corner_radius=4)
        self.bar_frame.pack(fill="x", pady=(0, 4))
        
        self.strength_bar = ctk.CTkProgressBar(
            self.bar_frame, height=8, corner_radius=4
        )
        self.strength_bar.pack(fill="x")
        self.strength_bar.set(0)
        
        # Strength label
        self.strength_label = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=12)
        )
        self.strength_label.pack(anchor="w")
    
    def update_strength(self, score: int, strength: str):
        """
        Update the strength meter.
        
        Args:
            score: 0-100 strength score
            strength: Strength label (Weak, Fair, Good, Strong)
        """
        # Update bar
        self.current_score = score
        self.strength_bar.set(score / 100)
        
        # Update color based on strength
        colors = {
            "Weak": "#e74c3c",
            "Fair": "#f39c12", 
            "Good": "#3498db",
            "Strong": "#2ecc71"
        }
        color = colors.get(strength, "#e74c3c")
        self.strength_bar.configure(progress_color=color)
        
        # Update label
        self.strength_label.configure(text=f"{strength} ({score}%)", text_color=color)

    def get_score(self) -> int:
        """Return the current strength score."""
        return self.current_score
=======
"""
Password strength meter widget.
"""
import customtkinter as ctk


class StrengthMeter(ctk.CTkFrame):
    """Visual password strength indicator."""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        self.configure(fg_color="transparent")
        self.current_score = 0
        
        # Strength bar
        self.bar_frame = ctk.CTkFrame(self, height=8, corner_radius=4)
        self.bar_frame.pack(fill="x", pady=(0, 4))
        
        self.strength_bar = ctk.CTkProgressBar(
            self.bar_frame, height=8, corner_radius=4
        )
        self.strength_bar.pack(fill="x")
        self.strength_bar.set(0)
        
        # Strength label
        self.strength_label = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=12)
        )
        self.strength_label.pack(anchor="w")
    
    def update_strength(self, score: int, strength: str):
        """
        Update the strength meter.
        
        Args:
            score: 0-100 strength score
            strength: Strength label (Weak, Fair, Good, Strong)
        """
        # Update bar
        self.current_score = score
        self.strength_bar.set(score / 100)
        
        # Update color based on strength
        colors = {
            "Weak": "#e74c3c",
            "Fair": "#f39c12", 
            "Good": "#3498db",
            "Strong": "#2ecc71"
        }
        color = colors.get(strength, "#e74c3c")
        self.strength_bar.configure(progress_color=color)
        
        # Update label
        self.strength_label.configure(text=f"{strength} ({score}%)", text_color=color)

    def get_score(self) -> int:
        """Return the current strength score."""
        return self.current_score
>>>>>>> 6b91baecfa0930c653d444e61194cb7690e1fceb
