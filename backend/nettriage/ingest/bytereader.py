"""Bounds-checked cursor over a byte buffer.

Every decoder in NetTriage reads packet bytes through this class, so there is
exactly one place where a length field from the capture can turn into a read.
A read past the end raises ``Truncated`` instead of returning short data.
"""

from __future__ import annotations

import struct


class DecodeError(Exception):
    """The bytes do not form a valid structure of the expected kind."""


class Truncated(DecodeError):
    """A read would run past the end of the available bytes."""


U8 = struct.Struct("B")
U16 = struct.Struct("!H")
U32 = struct.Struct("!I")


class ByteReader:
    __slots__ = ("_buf", "_pos", "_end")

    def __init__(self, buf: bytes | bytearray | memoryview, start: int = 0, end: int | None = None):
        size = len(buf)
        if end is None or end > size:
            end = size
        if start < 0 or start > end:
            raise Truncated(f"start {start} outside buffer of {size} bytes")
        self._buf = buf
        self._pos = start
        self._end = end

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def end(self) -> int:
        return self._end

    @property
    def remaining(self) -> int:
        return self._end - self._pos

    @property
    def buffer(self) -> bytes | bytearray | memoryview:
        return self._buf

    def _need(self, n: int) -> int:
        if n < 0:
            raise DecodeError(f"negative length {n}")
        start = self._pos
        if start + n > self._end:
            raise Truncated(f"need {n} bytes at offset {start}, have {self._end - start}")
        self._pos = start + n
        return start

    def unpack(self, st: struct.Struct) -> tuple:
        start = self._need(st.size)
        return st.unpack_from(self._buf, start)

    def u8(self) -> int:
        start = self._need(1)
        return self._buf[start]

    def u16(self) -> int:
        start = self._need(2)
        return U16.unpack_from(self._buf, start)[0]

    def u32(self) -> int:
        start = self._need(4)
        return U32.unpack_from(self._buf, start)[0]

    def take(self, n: int) -> bytes:
        start = self._need(n)
        return bytes(self._buf[start:start + n])

    def skip(self, n: int) -> None:
        self._need(n)

    def sub(self, n: int) -> ByteReader:
        """Return a reader over the next ``n`` bytes and advance past them."""
        start = self._need(n)
        return ByteReader(self._buf, start, start + n)

    def rest(self) -> ByteReader:
        """Return a reader over everything left and advance to the end."""
        return self.sub(self.remaining)

    def peek_u8(self) -> int:
        if self._pos >= self._end:
            raise Truncated(f"need 1 byte at offset {self._pos}, have 0")
        return self._buf[self._pos]

    def seek(self, pos: int) -> None:
        """Jump to an absolute offset inside this reader's window."""
        if pos < 0 or pos > self._end:
            raise Truncated(f"seek to {pos} outside window ending at {self._end}")
        self._pos = pos
