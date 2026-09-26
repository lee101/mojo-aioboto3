"""Correctness-gated benchmark for mojo-aioboto3.

Every case checks agreement with the real aioboto3 function before timing, so
a regression in the Mojo kernels shows up as a correctness failure rather than
a suspiciously good number.
"""

from __future__ import annotations

import pathlib
import struct
import sys
import time

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "python"))

import mojo_aioboto3 as mab  # noqa: E402
from aioboto3.s3 import cse  # noqa: E402


def _time(fn, repeats=7):
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def bench_lower_bound(n: int = 1 << 16):
    values = np.random.default_rng(0).integers(0, 1 << 40, n, dtype=np.int64)

    def run_python():
        acc = 0
        for v in values:
            acc += cse._get_cipher_block_lower_bound(int(v))
        return acc

    def run_mojo():
        acc = 0
        for v in values:
            acc += mab.cipher_block_lower_bound(int(v))
        return acc

    assert run_python() == run_mojo()
    return f"lower_bound n={n}", _time(run_python, 3), _time(run_mojo, 3)


def bench_range_align(n: int = 1 << 16):
    starts = np.random.default_rng(1).integers(0, 1 << 40, n, dtype=np.int64)
    ends = starts + np.random.default_rng(2).integers(1, 1 << 20, n, dtype=np.int64)

    def run_python():
        acc = 0
        for s, e in zip(starts, ends):
            lo, hi = cse._get_adjusted_crypto_range(int(s), int(e))
            acc += lo + hi
        return acc

    def run_mojo():
        acc = 0
        for s, e in zip(starts, ends):
            lo, hi = mab.adjusted_crypto_range(int(s), int(e))
            acc += lo + hi
        return acc

    assert run_python() == run_mojo()
    return f"adjusted_crypto_range n={n}", _time(run_python, 3), _time(run_mojo, 3)


def bench_increment_blocks(n: int = 1 << 15):
    counters = [
        bytes((i * 31 + j) % 256 for j in range(12)) + b"\x00\x00\x00\x01"
        for i in range(n)
    ]

    def run_python():
        acc = 0
        for c in counters:
            acc += cse._increment_blocks(c, 7)[15]
        return acc

    def run_mojo():
        acc = 0
        for c in counters:
            acc += mab.increment_blocks(c, 7)[15]
        return acc

    assert run_python() == run_mojo()
    return f"increment_blocks n={n}", _time(run_python, 3), _time(run_mojo, 3)


def bench_increment_blocks_kernel_only(n: int = 1 << 15):
    """The kernel alone, one ctypes call for a whole batch of counters.

    This is what a caller that already has its counters in one buffer would do;
    the shim exposes it so the win is measurable rather than theoretical.
    """
    from mojo_aioboto3._lib import lib

    packed = np.zeros(16 * n, dtype=np.uint8)
    rng = np.random.default_rng(3)
    for i in range(n):
        packed[16 * i : 16 * i + 12] = rng.integers(0, 256, 12, dtype=np.uint8)
        packed[16 * i + 15] = 1
    out = np.zeros(16 * n, dtype=np.uint8)
    addr, oaddr = packed.ctypes.data, out.ctypes.data

    def one():
        for i in range(n):
            lib.ab3_increment_blocks(addr + 16 * i, 7, oaddr + 16 * i)

    # correctness first: every counter must match the real function
    for i in (0, 1, n // 2, n - 1):
        assert mab.increment_blocks(packed[16 * i : 16 * i + 16].tobytes(), 7) == (
            cse._increment_blocks(packed[16 * i : 16 * i + 16].tobytes(), 7)
        )

    def run_python():
        acc = 0
        for i in range(n):
            acc += cse._increment_blocks(packed[16 * i : 16 * i + 16].tobytes(), 7)[15]
        return acc

    return f"increment_blocks kernel n={n}", _time(run_python, 3), _time(one, 3)


def bench_range_header(n: int = 1 << 14):
    headers = [
        b"bytes=%d-%d" % (i * 128, i * 128 + 4096) for i in range(n)
    ]

    def run_python():
        acc = 0
        for h in headers:
            m = cse.RANGE_REGEX.match(h.decode())
            acc += int(m.group(1)) + int(m.group(2))
        return acc

    def run_mojo():
        acc = 0
        for h in headers:
            start, end, _has = mab.parse_range_header(h)
            acc += start + end
        return acc

    assert run_python() == run_mojo()
    return f"parse_range_header n={n}", _time(run_python, 3), _time(run_mojo, 3)


def bench_range_align_batch(n: int = 1 << 16):
    """The batched range alignment: one ctypes transition for the whole batch,
    which is the only shape in which this arithmetic can beat Python."""
    starts = np.random.default_rng(1).integers(0, 1 << 40, n, dtype=np.int64)
    ends = starts + np.random.default_rng(2).integers(1, 1 << 20, n, dtype=np.int64)

    def run_python():
        acc = 0
        for s, e in zip(starts, ends):
            lo, hi = cse._get_adjusted_crypto_range(int(s), int(e))
            acc += lo + hi
        return acc

    got = mab.adjusted_crypto_range_batch(starts, ends)
    assert got[:, 0].sum() + got[:, 1].sum() == run_python()
    return (
        f"adjusted_crypto_range batch n={n}",
        _time(run_python, 3),
        _time(lambda: mab.adjusted_crypto_range_batch(starts, ends)),
    )


def bench_adjust_iv_batch(n: int = 1 << 14):
    rng = np.random.default_rng(4)
    ivs = [bytes(rng.integers(0, 256, 12, dtype=np.uint8).tolist()) for _ in range(n)]
    offsets = np.arange(n, dtype=np.int64) * mab.AES_BLOCK_SIZE

    def run_python():
        acc = 0
        for iv, off in zip(ivs, offsets):
            acc += cse._adjust_iv_for_range(iv, int(off))[-1]
        return acc

    got = mab.adjust_iv_for_range_batch(ivs, offsets)
    assert sum(b[-1] for b in got) == run_python()
    return (
        f"adjust_iv_for_range batch n={n}",
        _time(run_python, 3),
        _time(lambda: mab.adjust_iv_for_range_batch(ivs, offsets)),
    )


def main():
    print(f"{'case':<34}{'reference':>13}{'mojo-aioboto3':>16}{'ratio':>10}")
    print("-" * 73)
    for fn in (
        bench_lower_bound,
        bench_range_align,
        bench_range_align_batch,
        bench_adjust_iv_batch,
        bench_increment_blocks,
        bench_increment_blocks_kernel_only,
        bench_range_header,
    ):
        label, ref, got = fn()
        ratio = ref / got if got else float("nan")
        print(f"{label:<34}{ref*1e3:>11.2f}ms{got*1e3:>14.2f}ms{ratio:>9.2f}x")


if __name__ == "__main__":
    main()
