<<<<<<< HEAD
"""
Secure memory utilities for handling sensitive data.
Using bytearrays to allow manual zeroing of memory contents.
"""
import ctypes

def zero_memory(data: bytearray):
    """
    Overwrites the memory of a bytearray with zeros to prevent sensitive
    data from lingering in RAM.
    """
    if not isinstance(data, bytearray):
        return
    
    # Simple zero-out loop
    for i in range(len(data)):
        data[i] = 0

def secure_zero(obj):
    """
    Attempts to zero out various types of objects.
    Limited capability for immutable strings, but works for bytearrays.
    """
    if isinstance(obj, bytearray):
        zero_memory(obj)
    elif isinstance(obj, list):
        for item in obj:
            secure_zero(item)
    # Note: str and bytes are immutable in Python, cannot be zeroed in-place easily 
    # without deeper C-level hacks. We avoid using strings for keys.
=======
"""
Secure memory utilities for handling sensitive data.
Using bytearrays to allow manual zeroing of memory contents.
"""
import ctypes

def zero_memory(data: bytearray):
    """
    Overwrites the memory of a bytearray with zeros to prevent sensitive
    data from lingering in RAM.
    """
    if not isinstance(data, bytearray):
        return
    
    # Simple zero-out loop
    for i in range(len(data)):
        data[i] = 0

def secure_zero(obj):
    """
    Attempts to zero out various types of objects.
    Limited capability for immutable strings, but works for bytearrays.
    """
    if isinstance(obj, bytearray):
        zero_memory(obj)
    elif isinstance(obj, list):
        for item in obj:
            secure_zero(item)
    # Note: str and bytes are immutable in Python, cannot be zeroed in-place easily 
    # without deeper C-level hacks. We avoid using strings for keys.
>>>>>>> 6b91baecfa0930c653d444e61194cb7690e1fceb
