"""Text-based UI (TUI) for JoyfulJay.

The TUI is optional and only available when the `tui` extra is installed:

    pip install "joyfuljay[tui]"
"""

from __future__ import annotations

from .app import run_tui

__all__ = ["run_tui"]

