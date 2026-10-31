"""Turn untrusted bytes from packets into plain ASCII text.

Anything outside printable ASCII is escaped at decode time, so a hostname or
DNS name can never carry control characters, ANSI escapes or Unicode tricks
into the rest of the program.
"""

from __future__ import annotations

import re

_SAFE_LABEL = re.compile(rb"[A-Za-z0-9_\-*]*")


def escape_bytes(data: bytes, max_len: int = 255) -> str:
    """Printable ASCII is kept; everything else becomes \\xNN."""
    clipped = data[:max_len]
    out = []
    for b in clipped:
        if b == 0x5C:
            out.append("\\\\")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    if len(data) > max_len:
        out.append("...")
    return "".join(out)


def escape_dns_label(label: bytes) -> str:
    """dig-style escaping: '.', '\\' and non-printables become \\DDD."""
    if _SAFE_LABEL.fullmatch(label):
        return label.decode("ascii")
    out = []
    for b in label:
        if 0x21 <= b <= 0x7E and b not in (0x2E, 0x5C):
            out.append(chr(b))
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)
