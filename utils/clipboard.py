<<<<<<< HEAD
"""
Clipboard utilities with auto-clear functionality.
"""
import threading
import time
from typing import Optional

try:
    import pyperclip
    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False

from config import CLIPBOARD_CLEAR_SECONDS


class ClipboardManager:
    """Manages clipboard operations with auto-clear for security."""
    
    _clear_timer: Optional[threading.Timer] = None
    _last_copied: Optional[str] = None
    
    @classmethod
    def copy(cls, text: str, auto_clear: bool = True, 
             clear_seconds: int = CLIPBOARD_CLEAR_SECONDS) -> bool:
        """
        Copy text to clipboard with optional auto-clear.
        
        Args:
            text: Text to copy
            auto_clear: Whether to auto-clear after timeout
            clear_seconds: Seconds before clearing
            
        Returns:
            True if successful, False otherwise
        """
        if not PYPERCLIP_AVAILABLE:
            return False
        
        try:
            # Cancel any existing timer
            if cls._clear_timer:
                cls._clear_timer.cancel()
            
            pyperclip.copy(text)
            cls._last_copied = text
            
            if auto_clear:
                cls._clear_timer = threading.Timer(
                    clear_seconds, 
                    cls._clear_if_unchanged
                )
                cls._clear_timer.daemon = True
                cls._clear_timer.start()
            
            return True
        except Exception:
            return False
    
    @classmethod
    def _clear_if_unchanged(cls):
        """Clear clipboard only if content hasn't changed."""
        try:
            current = pyperclip.paste()
            if current == cls._last_copied:
                pyperclip.copy("")
                cls._last_copied = None
        except Exception:
            pass
    
    @classmethod
    def clear(cls):
        """Immediately clear clipboard."""
        if cls._clear_timer:
            cls._clear_timer.cancel()
        
        if PYPERCLIP_AVAILABLE:
            try:
                pyperclip.copy("")
                cls._last_copied = None
            except Exception:
                pass
=======
"""
Clipboard utilities with auto-clear functionality.
"""
import threading
import time
from typing import Optional

try:
    import pyperclip
    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False

from config import CLIPBOARD_CLEAR_SECONDS


class ClipboardManager:
    """Manages clipboard operations with auto-clear for security."""
    
    _clear_timer: Optional[threading.Timer] = None
    _last_copied: Optional[str] = None
    
    @classmethod
    def copy(cls, text: str, auto_clear: bool = True, 
             clear_seconds: int = CLIPBOARD_CLEAR_SECONDS) -> bool:
        """
        Copy text to clipboard with optional auto-clear.
        
        Args:
            text: Text to copy
            auto_clear: Whether to auto-clear after timeout
            clear_seconds: Seconds before clearing
            
        Returns:
            True if successful, False otherwise
        """
        if not PYPERCLIP_AVAILABLE:
            return False
        
        try:
            # Cancel any existing timer
            if cls._clear_timer:
                cls._clear_timer.cancel()
            
            pyperclip.copy(text)
            cls._last_copied = text
            
            if auto_clear:
                cls._clear_timer = threading.Timer(
                    clear_seconds, 
                    cls._clear_if_unchanged
                )
                cls._clear_timer.daemon = True
                cls._clear_timer.start()
            
            return True
        except Exception:
            return False
    
    @classmethod
    def _clear_if_unchanged(cls):
        """Clear clipboard only if content hasn't changed."""
        try:
            current = pyperclip.paste()
            if current == cls._last_copied:
                pyperclip.copy("")
                cls._last_copied = None
        except Exception:
            pass
    
    @classmethod
    def clear(cls):
        """Immediately clear clipboard."""
        if cls._clear_timer:
            cls._clear_timer.cancel()
        
        if PYPERCLIP_AVAILABLE:
            try:
                pyperclip.copy("")
                cls._last_copied = None
            except Exception:
                pass
>>>>>>> 6b91baecfa0930c653d444e61194cb7690e1fceb
