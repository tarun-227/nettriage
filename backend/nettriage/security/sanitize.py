"""Make strings safe to show, whatever produced them.

Decoders already escape packet bytes to printable ASCII. This is the second
line of defence, applied to every string in a Report: it removes control
characters, ANSI escapes and Unicode direction overrides (the "Trojan Source"
trick), and caps the length.
"""

from __future__ import annotations

import re

_UNSAFE = re.compile(
    "["
    "\x00-\x1f\x7f-\x9f"          # C0 and C1 controls, including ESC
    "​-‏"               # zero-width characters and direction marks
    "‪-‮"               # bidi embeddings and overrides
    "⁦-⁩"               # bidi isolates
    "﻿"                      # BOM / zero-width no-break space
    "]"
)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def display_safe(value: str, max_len: int = 512) -> str:
    if len(value) > max_len:
        value = value[:max_len] + "..."
    return _UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}", value)


def strip_ansi(value: str) -> str:
    return _ANSI.sub("", value)


def csv_safe(value: str) -> str:
    """Stop spreadsheets from treating a cell as a formula."""
    if value and value[0] in "=+-@\t\r":
        return "'" + value
    return value
