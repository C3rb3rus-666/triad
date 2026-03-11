"""Core package exports for TRIAD.

This module exposes top-level classes to improve IDE autocompletion
and typing across the workspace.
"""

from .bridge import CommunicationBridge

# TriadOrchestrator imported lazily to avoid circular imports
__all__ = ["CommunicationBridge"]
