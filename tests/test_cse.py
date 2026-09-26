"""Parity against `aioboto3.s3.cse`.

Every function in this module is a 64-bit or byte operation: block alignment,
a big-endian counter increment, an HTTP Range header scan. None of them
approximates anything, so the assertions are exact equality against the real
aioboto3 functions.
"""

import os

import pytest

import mojo_aioboto3 as mab
from conftest import cse, real_range

BLOCK = mab.AES_BLOCK_SIZE


def _iv(seed=0):
    return bytes((i * 37 + seed) % 256 for i in range(12))


# ---------------------------------------------------------------------------
# Cipher-block alignment
# ---------------------------------------------------------------------------

BOUND_VALUES = [
    0, 1, 63, 64, 127, 128, 129, 200, 255, 256, 1000, 4095, 4096, 65535,
    1 << 20, (1 << 31) - 1, 1 << 40,
]


@pytest.mark.parametrize("value", BOUND_VALUES)
def test_cipher_block_lower_bound_matches_aioboto3(value):
    assert mab.cipher_block_lower_bound(value) == cse()._get_cipher_block_lower_bound(value)


@pytest.mark.parametrize("value", BOUND_VALUES)
def test_cipher_block_upper_bound_matches_aioboto3(value):
    assert mab.cipher_block_upper_bound(value) == cse()._get_cipher_block_upper_bound(value)


def test_lower_bound_never_goes_negative():
    for value in (0, 1, 5, 127, 128):
        assert mab.cipher_block_lower_bound(value) == 0


def test_lower_bound_is_one_block_below_the_containing_block():
    v = 1000
    assert mab.cipher_block_lower_bound(v) == (v // BLOCK) * BLOCK - BLOCK


def test_upper_bound_is_one_block_above_the_next_block():
    v = 1000
    assert mab.cipher_block_upper_bound(v) == (v // BLOCK + 2) * BLOCK


def test_upper_bound_saturates_at_the_java_long_maximum():
    huge = mab.JAVA_LONG_MAX_VALUE
    assert mab.cipher_block_upper_bound(huge) == huge
    assert mab.cipher_block_upper_bound(huge - 10) == huge


@pytest.mark.parametrize(
    "start,end",
    [(0, 0), (1, 1), (100, 200), (127, 128), (128, 129), (5000, 9000),
     (1 << 30, (1 << 30) + 7)],
)
def test_adjusted_crypto_range_matches_aioboto3(start, end):
    assert mab.adjusted_crypto_range(start, end) == tuple(
        cse()._get_adjusted_crypto_range(start, end)
    )


def test_adjusted_crypto_range_actually_contains_the_request():
    for start, end in [(100, 200), (0, 1), (4096, 4097), (999999, 1000001)]:
        lo, hi = mab.adjusted_crypto_range(start, end)
        assert lo <= start and end <= hi
        assert lo % BLOCK == 0 and hi % BLOCK == 0


# ---------------------------------------------------------------------------
# GCM J0 and the CTR counter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(6))
def test_compute_j0_matches_aioboto3(seed):
    iv = _iv(seed)
    assert mab.compute_j0(iv) == cse()._compute_j0(iv)


def test_compute_j0_layout():
    """J0 is the IV, three zero bytes and a block counter of 2."""
    iv = _iv(1)
    j0 = mab.compute_j0(iv)
    assert len(j0) == 16
    assert j0[:12] == iv
    assert j0[12:15] == b"\x00\x00\x00"
    assert j0[15] == 2


def test_compute_j0_rejects_a_short_iv():
    with pytest.raises(ValueError):
        mab.compute_j0(b"\x00" * 11)


@pytest.mark.parametrize("delta", [0, 1, 2, 255, 256, 65535, 65536, 1 << 20, 1 << 31])
def test_increment_blocks_matches_aioboto3(delta):
    counter = _iv(2) + b"\x00\x00\x00\x01"
    assert mab.increment_blocks(counter, delta) == cse()._increment_blocks(
        counter, delta
    )


def test_increment_blocks_carries_across_the_whole_field():
    counter = _iv(3) + b"\x00\x00\xff\xff"
    got = mab.increment_blocks(counter, 1)
    assert got[12:] == b"\x00\x01\x00\x00"
    assert got[:12] == _iv(3)


def test_increment_blocks_zero_delta_is_a_copy():
    counter = _iv(4) + b"\xab\xcd\xef\x01"
    assert mab.increment_blocks(counter, 0) == counter


def test_increment_blocks_rejects_a_wrong_sized_counter():
    with pytest.raises(ValueError):
        mab.increment_blocks(b"\x00" * 15, 1)


def test_increment_blocks_overflow_raises():
    counter = _iv(5) + b"\x00\x00\x00\x00"
    with pytest.raises(OverflowError):
        mab.increment_blocks(counter, mab.JAVA_LONG_MAX_VALUE + 1)


# ---------------------------------------------------------------------------
# Ranged IV adjustment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("blocks", [0, 1, 2, 7, 255, 256, 65535, 1 << 20])
def test_adjust_iv_for_range_matches_aioboto3(blocks):
    iv = _iv(6)
    offset = blocks * BLOCK
    assert mab.adjust_iv_for_range(iv, offset) == cse()._adjust_iv_for_range(iv, offset)


def test_adjust_iv_is_j0_plus_the_block_delta():
    iv = _iv(7)
    for blocks in (0, 1, 9, 1000):
        got = mab.adjust_iv_for_range(iv, blocks * BLOCK)
        assert got == mab.increment_blocks(mab.compute_j0(iv), blocks)


def test_adjust_iv_rejects_a_misaligned_offset():
    """The real function raises RuntimeError here; the kernel reports -2 and the
    shim turns it into a ValueError."""
    with pytest.raises(RuntimeError):
        cse()._adjust_iv_for_range(_iv(8), 5)
    with pytest.raises(ValueError):
        mab.adjust_iv_for_range(_iv(8), 5)


@pytest.mark.parametrize("offset", [1, 5, 127, 129, BLOCK - 1, BLOCK + 1])
def test_adjust_iv_rejects_every_misalignment(offset):
    with pytest.raises(ValueError):
        mab.adjust_iv_for_range(_iv(9), offset)


def test_adjust_iv_rejects_a_short_iv():
    with pytest.raises(ValueError):
        mab.adjust_iv_for_range(b"\x00" * 11, 0)


# ---------------------------------------------------------------------------
# Range header parsing
# ---------------------------------------------------------------------------

RANGE_HEADERS = [
    b"bytes=0-0",
    b"bytes=0-",
    b"bytes=100-200",
    b"bytes=127-128",
    b"bytes=128-129",
    b"bytes=4096-8191",
    b"bytes=0-9223372036854775806",
    b"bytes=0000000123-0000456",
    b"bytes=9223372036854775807-9223372036854775807",
]


@pytest.mark.parametrize("value", RANGE_HEADERS)
def test_parse_range_header_matches_the_regex(value):
    start, end, has_end = mab.parse_range_header(value)
    m = cse().RANGE_REGEX.match(value.decode())
    assert start == int(m.group(1))
    if has_end:
        assert end == int(m.group(2))
    else:
        assert end == -1
        assert m.group(2) is None


def test_open_ended_range_uses_the_documented_default():
    start, end, has_end = mab.parse_range_header(b"bytes=5-")
    assert (start, has_end) == (5, False)
    # S3CSE.get_object substitutes this when group(2) is None
    assert end == -1
    assert mab.OPEN_ENDED_DEFAULT == 9223372036854775806


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"bytes",
        b"bytes=",
        b"bytes=-",
        b"bytes=abc",
        b"items=0-1",
        b"bytes=1",
        b" bytes=1-2",
        b"bytes=+1-2",
    ],
)
def test_parse_range_header_rejects_what_the_regex_rejects(bad):
    assert cse().RANGE_REGEX.match(bad.decode()) is None
    with pytest.raises(ValueError):
        mab.parse_range_header(bad)


def test_parse_range_header_rejects_an_overflowing_start():
    assert cse().RANGE_REGEX.match("bytes=99999999999999999999-1") is not None
    with pytest.raises(OverflowError):
        mab.parse_range_header(b"bytes=99999999999999999999-1")


def test_parse_range_header_saturates_an_overflowing_end():
    """`int()` in Python is unbounded, so upstream would keep the exact huge
    value; the kernel saturates at the Java long maximum instead, since the ABI
    has nowhere to put a bigger one. The difference is asserted, not hidden."""
    start, end, has_end = mab.parse_range_header(
        b"bytes=0-99999999999999999999999"
    )
    assert (start, has_end) == (0, True)
    assert end == mab.JAVA_LONG_MAX_VALUE


def test_parse_range_header_agrees_with_the_real_get_object_default():
    for value in (b"bytes=100-200", b"bytes=0-"):
        mine = mab.parse_range_header(value)
        theirs = real_range(value.decode())
        if mine[2]:
            assert (mine[0], mine[1]) == theirs
        else:
            assert mine[0] == theirs[0]
            assert theirs[1] == mab.OPEN_ENDED_DEFAULT


# ---------------------------------------------------------------------------
# AEAD tag trimming
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "desired,length,tag",
    [
        (0, 128, 16),
        (16, 128, 16),
        (100, 128, 16),
        (111, 128, 16),
        (112, 128, 16),
        (10_000, 20_000, 16),
        (19_983, 20_000, 16),
    ],
)
def test_trim_end_matches_the_v2_expression(desired, length, tag):
    max_offset = length - tag - 1
    expect = max_offset if desired > max_offset else desired
    assert mab.trim_end(desired, length, tag) == expect


def test_trim_end_uses_the_tag_length_not_the_block_size():
    """A kernel that hardcoded 16 bytes would pass the tests above; this one
    does not."""
    assert mab.trim_end(1000, 1024, 16) == 1000
    assert mab.trim_end(1000, 1024, 128) == 895
    assert mab.trim_end(1000, 1024, 0) == 1000


def test_parse_range_header_ignores_trailing_bytes_like_the_regex():
    """`re.match` is not `fullmatch`: `bytes=1-2-3` and `bytes=1-2 ` both match
    the prefix, and the kernel has to agree or the parity claim is false."""
    assert cse().RANGE_REGEX.match("bytes=1-2-3").group(2) == "2"
    assert cse().RANGE_REGEX.match("bytes=1-2 ").group(2) == "2"
    assert mab.parse_range_header(b"bytes=1-2-3") == (1, 2, True)
    assert mab.parse_range_header(b"bytes=1-2 ") == (1, 2, True)


# ---------------------------------------------------------------------------
# Batched forms
# ---------------------------------------------------------------------------


def test_adjusted_crypto_range_batch_matches_the_scalar_form():
    starts = [0, 1, 127, 128, 129, 1000, 4096, 1 << 30]
    ends = [0, 1, 127, 128, 129, 1000, 4096, (1 << 30) + 7]
    got = mab.adjusted_crypto_range_batch(starts, ends)
    assert [tuple(int(x) for x in row) for row in got] == [
        tuple(cse()._get_adjusted_crypto_range(s, e)) for s, e in zip(starts, ends)
    ]


def test_adjusted_crypto_range_batch_is_empty_safe():
    assert mab.adjusted_crypto_range_batch([], []).shape == (0, 2)


def test_adjusted_crypto_range_batch_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        mab.adjusted_crypto_range_batch([1, 2], [3])


def test_adjust_iv_for_range_batch_matches_the_scalar_form():
    ivs = [_iv(k) for k in range(8)]
    offsets = [k * BLOCK for k in range(8)]
    got = mab.adjust_iv_for_range_batch(ivs, offsets)
    assert got == [cse()._adjust_iv_for_range(iv, off) for iv, off in zip(ivs, offsets)]


def test_adjust_iv_for_range_batch_agrees_with_itself():
    ivs = [_iv(k) for k in range(64)]
    offsets = [k * BLOCK * 3 for k in range(64)]
    batch = mab.adjust_iv_for_range_batch(ivs, offsets)
    for iv, off, block in zip(ivs, offsets, batch):
        assert block == mab.adjust_iv_for_range(iv, off)


def test_adjust_iv_for_range_batch_zeroes_a_misaligned_entry():
    """One bad offset must not corrupt the others."""
    ivs = [_iv(0), _iv(1), _iv(2)]
    offsets = [0, 5, 2 * BLOCK]
    got = mab.adjust_iv_for_range_batch(ivs, offsets)
    assert got[0] == mab.adjust_iv_for_range(ivs[0], 0)
    assert got[1] == b"\x00" * 16
    assert got[2] == mab.adjust_iv_for_range(ivs[2], 2 * BLOCK)


def test_adjust_iv_for_range_batch_validates_lengths():
    with pytest.raises(ValueError):
        mab.adjust_iv_for_range_batch([b"\x00" * 11], [0])
    with pytest.raises(ValueError):
        mab.adjust_iv_for_range_batch([_iv(0)], [0, 128])
