"""Read-only static analysis for Windows Portable Executable files."""

from .pe import PEFormatError, analyze_pe

__all__ = ["PEFormatError", "analyze_pe"]
