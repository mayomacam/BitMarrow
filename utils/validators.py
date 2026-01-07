"""
Security policy validators for passwords and authentication.
"""
import re
from generators.password_generator import PasswordGenerator
from config import MIN_PASSWORD_LENGTH

class PasswordValidator:
    """Enforces the strict security policy for master and login passwords."""
    
    @staticmethod
    def validate(password: str) -> dict:
        """
        Validate password against strict policy:
        1. Length >= MIN_PASSWORD_LENGTH (12)
        2. Uppercase, Lowercase, Number, Symbol
        3. Strength score >= 60 (Good)
        """
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        strength_data = PasswordGenerator.calculate_strength(password)
        score = strength_data['score']
        
        results = {
            'length': len(password) >= MIN_PASSWORD_LENGTH,
            'uppercase': has_upper,
            'lowercase': has_lower,
            'number': has_digit,
            'symbol': has_symbol,
            'strength': score >= 50,
            'score': score,
            'strength_label': strength_data['strength']
        }
        
        results['is_valid'] = all([
            results['length'],
            results['uppercase'],
            results['lowercase'],
            results['number'],
            results['symbol'],
            results['strength']
        ])
        
        return results
class TOTPCodeValidator:
    """Validates TOTP codes."""
    
    @staticmethod
    def validate(code: str) -> bool:
        """Validates that the TOTP code is a 6-digit numeric string."""
        return bool(re.fullmatch(r'\d{6}', code))   