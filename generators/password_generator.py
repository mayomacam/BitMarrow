"""
Password generator with multiple generation modes.
Uses cryptographically secure random number generation.
"""
import secrets
import string
import re
from typing import List, Set, Optional
from dataclasses import dataclass
from enum import Enum

from config import (
    SIMILAR_CHARS, UPPERCASE, LOWERCASE, NUMBERS, SYMBOLS, BRACKETS,
    DEFAULT_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
)


class PasswordType(Enum):
    """Types of passwords that can be generated."""
    STANDARD = "standard"
    PASSPHRASE = "passphrase"
    PIN = "pin"
    MEMORABLE = "memorable"
    PATTERN = "pattern"
    HEX = "hex"


@dataclass
class PasswordOptions:
    """Options for password generation."""
    length: int = DEFAULT_PASSWORD_LENGTH
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_numbers: bool = True
    use_symbols: bool = True
    use_brackets: bool = False
    custom_chars: str = ""
    similar_randomization: bool = True  # Randomly swap similar chars
    start_with_letter: bool = False
    min_uppercase: int = 0
    min_lowercase: int = 0
    min_numbers: int = 0
    min_symbols: int = 0


# EFF Diceware wordlist (subset for demo - in production use full list)
WORDLIST = [
    "correct", "horse", "battery", "staple", "apple", "banana", "cherry",
    "dragon", "eagle", "falcon", "guitar", "hammer", "igloo", "jungle",
    "kitten", "lemon", "mango", "needle", "orange", "piano", "queen",
    "rabbit", "silver", "tiger", "umbrella", "violet", "wallet", "xenon",
    "yellow", "zebra", "anchor", "bridge", "castle", "diamond", "engine",
    "forest", "garden", "harbor", "island", "jacket", "kingdom", "lantern",
    "mountain", "nectar", "ocean", "pepper", "quartz", "river", "sunset",
    "thunder", "valley", "window", "crystal", "breeze", "shadow", "phoenix",
    "glacier", "meadow", "whisper", "crimson", "velvet", "mystic", "cosmic"
]

# Syllables for memorable passwords
CONSONANTS = "bcdfghjklmnpqrstvwxyz"
VOWELS = "aeiou"


class PasswordGenerator:
    """Generates various types of secure passwords."""
    
    def generate(self, password_type: PasswordType, 
                 options: Optional[PasswordOptions] = None) -> str:
        """
        Generate a password of the specified type.
        
        Args:
            password_type: Type of password to generate
            options: Generation options
            
        Returns:
            Generated password
        """
        options = options or PasswordOptions()
        
        generators = {
            PasswordType.STANDARD: self._generate_standard,
            PasswordType.PASSPHRASE: self._generate_passphrase,
            PasswordType.PIN: self._generate_pin,
            PasswordType.MEMORABLE: self._generate_memorable,
            PasswordType.PATTERN: self._generate_pattern,
            PasswordType.HEX: self._generate_hex,
        }
        
        generator = generators.get(password_type, self._generate_standard)
        password = generator(options)
        
        # Apply similar character randomization if enabled
        if options.similar_randomization:
            password = self._apply_similar_randomization(password)
        
        return password

    def suggest(self, password_type: PasswordType, 
                options: Optional[PasswordOptions] = None, 
                count: int = 4) -> List[str]:
        """Generate multiple password suggestions based on options."""
        return [self.generate(password_type, options) for _ in range(count)]
    
    def _build_charset(self, options: PasswordOptions) -> str:
        """Build character set based on options."""
        charset = ""
        if options.use_uppercase:
            charset += UPPERCASE
        if options.use_lowercase:
            charset += LOWERCASE
        if options.use_numbers:
            charset += NUMBERS
        if options.use_symbols:
            charset += SYMBOLS
        if options.use_brackets:
            charset += BRACKETS
        if options.custom_chars:
            charset += options.custom_chars
        
        # Remove duplicates while preserving order
        seen = set()
        unique_charset = ""
        for c in charset:
            if c not in seen:
                seen.add(c)
                unique_charset += c
        
        return unique_charset or LOWERCASE + NUMBERS
    
    def _generate_standard(self, options: PasswordOptions) -> str:
        """Generate a standard password with customizable character sets."""
        charset = self._build_charset(options)
        length = max(MIN_PASSWORD_LENGTH, min(options.length, MAX_PASSWORD_LENGTH))
        
        # Ensure minimum requirements are met
        password_chars = []
        
        if options.min_uppercase > 0 and options.use_uppercase:
            password_chars.extend(secrets.choice(UPPERCASE) for _ in range(options.min_uppercase))
        if options.min_lowercase > 0 and options.use_lowercase:
            password_chars.extend(secrets.choice(LOWERCASE) for _ in range(options.min_lowercase))
        if options.min_numbers > 0 and options.use_numbers:
            password_chars.extend(secrets.choice(NUMBERS) for _ in range(options.min_numbers))
        if options.min_symbols > 0 and options.use_symbols:
            password_chars.extend(secrets.choice(SYMBOLS) for _ in range(options.min_symbols))
        
        # Fill remaining length
        remaining = length - len(password_chars)
        password_chars.extend(secrets.choice(charset) for _ in range(remaining))
        
        # Shuffle the password
        password_list = list(password_chars)
        secrets.SystemRandom().shuffle(password_list)
        
        # Ensure starts with letter if required
        if options.start_with_letter:
            letters = UPPERCASE + LOWERCASE
            available_letters = [c for c in password_list if c in letters]
            if available_letters:
                # Move a letter to the front
                letter = secrets.choice(available_letters)
                password_list.remove(letter)
                password_list.insert(0, letter)
            else:
                # Add a letter at the start
                password_list[0] = secrets.choice(letters)
        
        return ''.join(password_list)
    
    def _generate_passphrase(self, options: PasswordOptions) -> str:
        """Generate a passphrase using random words."""
        # Use length to determine word count (roughly 4 chars per word + separator)
        word_count = max(4, options.length // 6)
        words = [secrets.choice(WORDLIST) for _ in range(word_count)]
        
        # Capitalize first letter of each word
        words = [w.capitalize() for w in words]
        
        # Add a number and symbol for extra entropy
        separator = secrets.choice(["-", "_", "."])
        passphrase = separator.join(words)
        
        if options.use_numbers:
            passphrase += str(secrets.randbelow(100))
        if options.use_symbols:
            passphrase += secrets.choice("!@#$%")
        
        return passphrase
    
    def _generate_pin(self, options: PasswordOptions) -> str:
        """Generate a numeric PIN."""
        length = max(4, min(options.length, 12))
        return ''.join(str(secrets.randbelow(10)) for _ in range(length))
    
    def _generate_memorable(self, options: PasswordOptions) -> str:
        """Generate a pronounceable memorable password."""
        password = ""
        
        # Generate syllables
        syllable_count = max(3, options.length // 4)
        for _ in range(syllable_count):
            password += secrets.choice(CONSONANTS)
            password += secrets.choice(VOWELS)
            if secrets.randbelow(2):
                password += secrets.choice(CONSONANTS)
        
        # Capitalize some letters
        password_list = list(password)
        for i in range(len(password_list)):
            if secrets.randbelow(4) == 0:
                password_list[i] = password_list[i].upper()
        
        # Add numbers and symbols
        if options.use_numbers:
            password_list.append(str(secrets.randbelow(100)))
        if options.use_symbols:
            password_list.append(secrets.choice("!@#$%^&*"))
        
        return ''.join(password_list)[:options.length]
    
    def _generate_pattern(self, options: PasswordOptions, 
                          pattern: str = "Cvcc-9999-ccvc") -> str:
        """
        Generate password based on a pattern.
        
        Pattern characters:
        - c: lowercase consonant
        - v: lowercase vowel
        - C: uppercase consonant
        - V: uppercase vowel
        - 9: digit
        - #: symbol
        - Other characters are kept as-is
        """
        result = ""
        for char in pattern:
            if char == 'c':
                result += secrets.choice(CONSONANTS)
            elif char == 'v':
                result += secrets.choice(VOWELS)
            elif char == 'C':
                result += secrets.choice(CONSONANTS.upper())
            elif char == 'V':
                result += secrets.choice(VOWELS.upper())
            elif char == '9':
                result += str(secrets.randbelow(10))
            elif char == '#':
                result += secrets.choice(SYMBOLS)
            else:
                result += char
        
        return result
    
    def _generate_hex(self, options: PasswordOptions) -> str:
        """Generate a hexadecimal string."""
        # Each hex char represents 4 bits
        byte_count = max(8, options.length // 2)
        return secrets.token_hex(byte_count)[:options.length]
    
    def _apply_similar_randomization(self, password: str) -> str:
        """Randomly swap 1+ similar characters for extra entropy."""
        if not password:
            return password
        
        password_list = list(password)
        similar_positions = []
        
        # Find positions with similar characters
        for i, char in enumerate(password_list):
            if char in SIMILAR_CHARS:
                similar_positions.append(i)
        
        # Randomly swap 1 to 3 similar characters (if available)
        if similar_positions:
            swap_count = min(len(similar_positions), secrets.randbelow(3) + 1)
            positions_to_swap = secrets.SystemRandom().sample(
                similar_positions, swap_count
            )
            
            for pos in positions_to_swap:
                char = password_list[pos]
                alternatives = SIMILAR_CHARS[char]
                password_list[pos] = secrets.choice(alternatives)
        
        return ''.join(password_list)
    
    @staticmethod
    def calculate_strength(password: str) -> dict:
        """
        Calculate password strength score with advanced heuristic analysis.
        
        Returns:
            Dictionary with score (0-100) and feedback
        """
        if not password:
            return {'score': 0, 'strength': "Empty", 'feedback': ["Password cannot be empty"]}

        score = 0
        feedback = []
        length = len(password)
        
        # 1. Length scoring (Base)
        if length >= 8: score += 10
        if length >= 12: score += 20
        if length >= 16: score += 20
        if length >= 24: score += 10
        
        # 2. Character variety
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        variety_count = sum([has_upper, has_lower, has_digit, has_symbol])
        score += variety_count * 10
        
        # 3. Security Bonus
        # Bonus for using all 4 character types
        if variety_count == 4:
            score += 10
        
        # 4. Pattern Penalties (Deductions)
        # Repeated characters (e.g., 'aaaa')
        repeats = len(re.findall(r'(.)\1{2,}', password))
        if repeats > 0:
            score -= repeats * 10
            feedback.append("Avoid long sequences of repeated characters")
            
        # Sequential characters (e.g., 'abc', '123')
        sequences = 0
        for i in range(len(password) - 2):
            chunk = password[i:i+3].lower()
            # Alpha sequence
            if ord(chunk[1]) == ord(chunk[0]) + 1 and ord(chunk[2]) == ord(chunk[1]) + 1:
                sequences += 1
            # Numeric sequence
            if chunk.isdigit() and int(chunk[1]) == int(chunk[0]) + 1 and int(chunk[2]) == int(chunk[1]) + 1:
                sequences += 1
        
        if sequences > 0:
            score -= sequences * 5
            feedback.append("Avoid common sequences like 'abc' or '123'")

        # 5. Common Passwords Check
        common = ["password", "qwerty", "admin123", "welcome", "12345678", "BitMarrow"]
        if password.lower() in common:
            score = 10
            feedback.append("This is a very common password")
        
        # Final normalization
        score = max(0, min(100, score))
        
        if score >= 90: strength = "Excellent"
        elif score >= 75: strength = "Strong"
        elif score >= 50: strength = "Good"
        elif score >= 30: strength = "Fair"
        else: strength = "Weak"
        
        # Add constructive feedback
        if length < 12: feedback.append("Use 12+ characters for better security")
        if variety_count < 3: feedback.append("Mix upper, lower, numbers, and symbols")
        
        return {
            'score': score,
            'strength': strength,
            'feedback': list(set(feedback)) # Unique feedback
        }
