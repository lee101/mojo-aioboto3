"""ctypes bridge to the compiled Mojo kernels.

The shared library owns no memory. Every buffer crosses the C ABI as a 64-bit
address, so the argtypes below stay `c_int64` for addresses; `c_int` truncates
them and segfaults.
"""

from __future__ import annotations

import ctypes
import pathlib

import numpy as np

_HERE = pathlib.Path(__file__).resolve()
_ROOT = _HERE.parents[2]
_LIB_PATH = _ROOT / "dist" / "libmojo-aioboto3.so"

_I = ctypes.c_int64

AES_BLOCK_SIZE = 128
JAVA_LONG_MAX_VALUE = 9223372036854775807
#: what `S3CSE.get_object` substitutes for a Range header with no end offset
OPEN_ENDED_DEFAULT = 9223372036854775806


def _load():
    if not _LIB_PATH.exists():
        raise RuntimeError(
            f"{_LIB_PATH} not found; run `bash build/build.sh` first"
        )
    lib = ctypes.CDLL(str(_LIB_PATH))

    lib.ab3_cipher_block_lower_bound.restype = ctypes.c_int64
    lib.ab3_cipher_block_lower_bound.argtypes = [_I]

    lib.ab3_cipher_block_upper_bound.restype = ctypes.c_int64
    lib.ab3_cipher_block_upper_bound.argtypes = [_I]

    lib.ab3_adjusted_crypto_range.restype = _I
    lib.ab3_adjusted_crypto_range.argtypes = [_I, _I, _I]

    lib.ab3_increment_blocks.restype = _I
    lib.ab3_increment_blocks.argtypes = [_I, _I, _I]

    lib.ab3_compute_j0.restype = _I
    lib.ab3_compute_j0.argtypes = [_I, _I]

    lib.ab3_adjust_iv_for_range.restype = _I
    lib.ab3_adjust_iv_for_range.argtypes = [_I, _I, _I]

    lib.ab3_parse_range_header.restype = _I
    lib.ab3_parse_range_header.argtypes = [_I, _I, _I]

    lib.ab3_trim_end.restype = ctypes.c_int64
    lib.ab3_trim_end.argtypes = [_I, _I, _I]

    lib.ab3_adjusted_crypto_range_batch.restype = _I
    lib.ab3_adjusted_crypto_range_batch.argtypes = [_I, _I, _I, _I]

    lib.ab3_adjust_iv_for_range_batch.restype = _I
    lib.ab3_adjust_iv_for_range_batch.argtypes = [_I, _I, _I, _I, _I]
    return lib


lib = _load()


def mab_max() -> int:
    return JAVA_LONG_MAX_VALUE


def _u8(buf) -> np.ndarray:
    if isinstance(buf, np.ndarray) and buf.dtype == np.uint8 and buf.flags.c_contiguous:
        return buf
    if isinstance(buf, (bytes, bytearray, memoryview)):
        return np.frombuffer(buf, dtype=np.uint8)
    return np.ascontiguousarray(buf, dtype=np.uint8)


def _i64(n: int) -> np.ndarray:
    return np.zeros(n, dtype=np.int64)


def cipher_block_lower_bound(value: int) -> int:
    """Block-aligned start for a ranged CSE GetObject, minus one block."""
    return int(lib.ab3_cipher_block_lower_bound(int(value)))


def cipher_block_upper_bound(value: int) -> int:
    """Block-aligned end for a ranged CSE GetObject, plus one block."""
    return int(lib.ab3_cipher_block_upper_bound(int(value)))


def adjusted_crypto_range(start: int, end: int) -> tuple[int, int]:
    """The (start, end) a ranged CSE GetObject must actually fetch."""
    out = _i64(2)
    lib.ab3_adjusted_crypto_range(int(start), int(end), out.ctypes.data)
    return int(out[0]), int(out[1])


def increment_blocks(counter: bytes, block_delta: int) -> bytes:
    """Advance a 16-byte AES-CTR counter block by `block_delta`."""
    if len(counter) != 16:
        raise ValueError("AES-CTR counter must be 16 bytes")
    if not -mab_max() <= block_delta <= mab_max():
        # the ABI carries the delta as a signed 64-bit integer, so an
        # out-of-range Python int would silently arrive as a negative one
        raise OverflowError(f"block_delta {block_delta} does not fit in int64")
    src = _u8(counter)
    dst = np.zeros(16, dtype=np.uint8)
    rc = lib.ab3_increment_blocks(
        src.ctypes.data, int(block_delta), dst.ctypes.data
    )
    if rc != 0:
        raise OverflowError(f"block_delta {block_delta} does not fit in int64")
    return dst.tobytes()


def compute_j0(iv: bytes) -> bytes:
    """The GCM pre-counter block J0 for a 12-byte IV."""
    if len(iv) != 12:
        raise ValueError("AES-GCM IV must be 12 bytes")
    src = _u8(iv)
    dst = np.zeros(16, dtype=np.uint8)
    if lib.ab3_compute_j0(src.ctypes.data, dst.ctypes.data) != 0:
        raise ValueError("could not derive J0")
    return dst.tobytes()


def adjust_iv_for_range(iv: bytes, byte_offset: int) -> bytes:
    """The CTR starting IV for a ranged decrypt at `byte_offset`."""
    if len(iv) != 12:
        raise ValueError("AES-GCM IV must be 12 bytes")
    if byte_offset < 0:
        raise ValueError("byte_offset must not be negative")
    src = _u8(iv)
    dst = np.zeros(16, dtype=np.uint8)
    rc = lib.ab3_adjust_iv_for_range(
        src.ctypes.data, int(byte_offset), dst.ctypes.data
    )
    if rc == -2:
        raise ValueError(
            f"byte_offset {byte_offset} is not a multiple of {AES_BLOCK_SIZE}"
        )
    if rc != 0:
        raise ValueError("could not adjust IV")
    return dst.tobytes()


def parse_range_header(value) -> tuple[int, int, bool]:
    """Parse a `Range` header into ``(start, end, has_end)``.

    `end` is -1 when the header has no end offset, which is the signal
    `S3CSE.get_object` uses to substitute `OPEN_ENDED_DEFAULT`. Raises
    `ValueError` for a value the RANGE_REGEX would not match.
    """
    src = _u8(value)
    out = _i64(4)
    rc = lib.ab3_parse_range_header(src.ctypes.data, src.size, out.ctypes.data)
    if rc == -1:
        raise OverflowError(f"range start does not fit in int64: {bytes(src)!r}")
    if rc != 0:
        raise ValueError(f"Dont understand this range value {bytes(src)!r}")
    return int(out[0]), int(out[1]), bool(out[2])


def adjusted_crypto_range_batch(starts, ends) -> np.ndarray:
    """`adjusted_crypto_range` for a whole batch; returns an ``(n, 2)`` array.

    One ctypes transition for the batch, which is the only way this arithmetic
    can beat the pure-Python version: a single call does a handful of integer
    operations, so the transition, not the arithmetic, is the cost.
    """
    s = np.ascontiguousarray(starts, dtype=np.int64).reshape(-1)
    e = np.ascontiguousarray(ends, dtype=np.int64).reshape(-1)
    if s.size != e.size:
        raise ValueError("starts and ends must be the same length")
    out = np.zeros(s.size * 2, dtype=np.int64)
    lib.ab3_adjusted_crypto_range_batch(
        s.ctypes.data, e.ctypes.data, s.size, out.ctypes.data
    )
    return out.reshape(-1, 2)


def adjust_iv_for_range_batch(ivs, byte_offsets) -> list:
    """`adjust_iv_for_range` for a batch of 12-byte IVs laid out contiguously.

    Returns one 16-byte counter block per input. A misaligned offset yields
    16 zero bytes for that entry, which cannot collide with a real counter
    block because a real one always ends in a non-zero low byte after J0.
    """
    flat = np.frombuffer(b"".join(ivs), dtype=np.uint8)
    if flat.size != 12 * len(ivs):
        raise ValueError("every IV must be 12 bytes")
    off = np.ascontiguousarray(byte_offsets, dtype=np.int64).reshape(-1)
    if off.size != flat.size // 12:
        raise ValueError("one byte offset per IV")
    out = np.zeros(16 * off.size, dtype=np.uint8)
    status = np.zeros(off.size, dtype=np.int64)
    lib.ab3_adjust_iv_for_range_batch(
        flat.ctypes.data, off.size, off.ctypes.data, out.ctypes.data, status.ctypes.data
    )
    blocks = out.reshape(-1, 16)
    for i in np.nonzero(status != 0)[0]:
        blocks[i] = 0
    return [bytes(row) for row in blocks]


def trim_end(desired_end: int, entire_file_length: int, aead_tag_len: int) -> int:
    """Clamp a range end so it stops before the GCM authentication tag."""
    return int(
        lib.ab3_trim_end(int(desired_end), int(entire_file_length), int(aead_tag_len))
    )
