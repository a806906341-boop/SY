"""
`chardet` is a library that provides character encoding auto-detection in Python.

Usage:
    >>> import chardet
    >>> chardet.detect(b'Hello, world!')
    {'encoding': 'ascii', 'confidence': 1.0, 'language': ''}

"""

from .__version__ import __version__
from .api import detect

__all__ = ["__version__", "detect"]
