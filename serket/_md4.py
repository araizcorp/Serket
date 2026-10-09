"""Pure-Python MD4 fallback (RFC 1320).

Some runtimes ship OpenSSL 3 without the legacy provider, so
``hashlib.new('MD4')`` raises ``ValueError: unsupported hash type MD4``.
ldap3 needs MD4 to derive the NT hash during NTLM authentication.

Resolution chain used by :func:`ensure_md4`:

1. Native ``hashlib`` MD4 (fastest, present on python.org builds).
2. ldap3's own fallback to pycryptodome (dependency of this project).
3. This vendored pure-Python implementation, registered into ``hashlib.new``
   so every caller (ldap3 included) keeps working unchanged.

Only imported when needed; on healthy runtimes the module is inert.
"""

from __future__ import annotations

import hashlib
import struct

__all__ = ["MD4", "ensure_md4"]


def _lrot(value: int, bits: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


class MD4:
    """Minimal hashlib-compatible MD4 implementation."""

    digest_size = 16
    block_size = 64
    name = "md4"

    def __init__(self, data: bytes = b"") -> None:
        self._count = 0
        self._buffer = bytearray()
        self._state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        if data:
            self.update(data)

    # -- hashing -----------------------------------------------------------
    def update(self, data: bytes) -> None:
        if isinstance(data, str):
            raise TypeError("MD4.update() requires bytes")
        self._buffer += data
        self._count += len(data)
        while len(self._buffer) >= 64:
            self._process(bytes(self._buffer[:64]))
            del self._buffer[:64]

    def _process(self, block: bytes) -> None:
        x = list(struct.unpack("<16I", block))
        a, b, c, d = self._state

        def f(x_, y_, z_):
            return (x_ & y_) | (~x_ & z_)

        def g(x_, y_, z_):
            return (x_ & y_) | (x_ & z_) | (y_ & z_)

        def h(x_, y_, z_):
            return x_ ^ y_ ^ z_

        # Round 1 — k = 0..15 in order, s = 3,7,11,19
        for i in range(16):
            s = (3, 7, 11, 19)[i % 4]
            if i % 4 == 0:
                a = _lrot(a + f(b, c, d) + x[i], s)
            elif i % 4 == 1:
                d = _lrot(d + f(a, b, c) + x[i], s)
            elif i % 4 == 2:
                c = _lrot(c + f(d, a, b) + x[i], s)
            else:
                b = _lrot(b + f(c, d, a) + x[i], s)

        # Round 2 — k order 0,4,8,12,1,5,9,13,...; s = 3,5,9,13; +0x5A827999
        order2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for i in range(16):
            s = (3, 5, 9, 13)[i % 4]
            k = x[order2[i]] + 0x5A827999
            if i % 4 == 0:
                a = _lrot(a + g(b, c, d) + k, s)
            elif i % 4 == 1:
                d = _lrot(d + g(a, b, c) + k, s)
            elif i % 4 == 2:
                c = _lrot(c + g(d, a, b) + k, s)
            else:
                b = _lrot(b + g(c, d, a) + k, s)

        # Round 3 — k order 0,8,4,12,2,10,...; s = 3,9,11,15; +0x6ED9EBA1
        order3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i in range(16):
            s = (3, 9, 11, 15)[i % 4]
            k = x[order3[i]] + 0x6ED9EBA1
            if i % 4 == 0:
                a = _lrot(a + h(b, c, d) + k, s)
            elif i % 4 == 1:
                d = _lrot(d + h(a, b, c) + k, s)
            elif i % 4 == 2:
                c = _lrot(c + h(d, a, b) + k, s)
            else:
                b = _lrot(b + h(c, d, a) + k, s)

        self._state[0] = (self._state[0] + a) & 0xFFFFFFFF
        self._state[1] = (self._state[1] + b) & 0xFFFFFFFF
        self._state[2] = (self._state[2] + c) & 0xFFFFFFFF
        self._state[3] = (self._state[3] + d) & 0xFFFFFFFF

    # -- hashlib-style API -------------------------------------------------
    def copy(self) -> "MD4":
        import copy as _copy

        return _copy.deepcopy(self)

    def digest(self) -> bytes:
        saved_state = list(self._state)
        saved_buffer = bytes(self._buffer)
        saved_count = self._count
        try:
            padding = b"\x80" + b"\x00" * ((56 - (saved_count + 1) % 64) % 64)
            self.update(padding + struct.pack("<Q", saved_count * 8))
            return struct.pack("<4I", *self._state)
        finally:
            self._state = saved_state
            self._buffer = bytearray(saved_buffer)
            self._count = saved_count

    def hexdigest(self) -> str:
        return self.digest().hex()


def ensure_md4() -> None:
    """Guarantee MD4 support in ``hashlib.new``.

    No-op when the runtime already provides MD4; otherwise transparently
    registers the vendored :class:`MD4` behind ``hashlib.new`` so ldap3's
    ``hashlib.new('MD4', ...)`` call keeps working.
    """
    try:
        hashlib.new("md4", b"")
        return
    except (ValueError, TypeError):
        pass

    _real_new = hashlib.new

    def _patched_new(name, data=b"", *args, **kwargs):
        if isinstance(name, str) and name.lower() == "md4":
            return MD4(data)
        return _real_new(name, data, *args, **kwargs)

    hashlib.new = _patched_new  # type: ignore[assignment]
