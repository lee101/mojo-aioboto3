"""Compiled counter arithmetic for aioboto3's S3 client-side encryption.

aioboto3 is a thin, synchronous-glue wrapper around boto3: `session.py`,
`resources/`, `dynamodb/table.py` and `s3/inject.py` are all resource factories
and parameter plumbing. The one place aioboto3 does arithmetic of its own is
`aioboto3/s3/cse.py`, the S3 client-side-encryption layer, and even there the
arithmetic is a narrow band: the AES-CTR/GCM counter block arithmetic needed to
serve a ranged GetObject, and the cipher-block alignment arithmetic that decides
which part of the ciphertext to fetch. Those are pure 64-bit and byte operations
and they run on every range request, so they are what this compilation unit
implements.

Everything else in cse.py -- AES-CBC, AES-GCM, PKCS7, the key contexts, the S3
calls -- is cryptography and I/O, and is left to the real package.

Every exported symbol takes buffer addresses as plain `Int` values and rebuilds
the pointer inside the body, because `@export` rejects parametric functions and
an inferred pointer origin would make the symbol parametric.
"""

comptime AES_BLOCK_SIZE = Int64(128)
comptime JAVA_LONG_MAX_VALUE = Int64(9223372036854775807)


def uptr(addr: Int) -> Pointer[UInt8, AnyOrigin[mut=True]]:
    return Pointer[UInt8, AnyOrigin[mut=True]](unsafe_from_address=addr)


def lptr(addr: Int) -> Pointer[Int64, AnyOrigin[mut=True]]:
    return Pointer[Int64, AnyOrigin[mut=True]](unsafe_from_address=addr)


# ---------------------------------------------------------------------------
# Cipher-block alignment for a ranged GetObject
# ---------------------------------------------------------------------------


@export("ab3_cipher_block_lower_bound")
def ab3_cipher_block_lower_bound(value: Int) abi("C") -> Int64:
    """Round `value` down to the AES block that contains it, minus one block.

    `_get_cipher_block_lower_bound`: the range has to start a block early so
    the CTR counter can be rewound to that block.
    """
    var v = Int64(value)
    var lower = v - (v % AES_BLOCK_SIZE) - AES_BLOCK_SIZE
    if lower < 0:
        return 0
    return lower


@export("ab3_cipher_block_upper_bound")
def ab3_cipher_block_upper_bound(value: Int) abi("C") -> Int64:
    """Round `value` up to the next AES block, plus one block.

    `_get_cipher_block_upper_bound`, saturating at Java's `long` maximum
    because the original is a port of the Java SDK.
    """
    var v = Int64(value)
    if v < 0:
        return 0
    var offset = AES_BLOCK_SIZE - (v % AES_BLOCK_SIZE)
    # saturate before each addition: a plain `v + offset + BLOCK` wraps negative
    # for an offset near the Java long maximum, which is exactly the input this
    # guard exists for
    var room = JAVA_LONG_MAX_VALUE - v
    if offset >= room:
        return JAVA_LONG_MAX_VALUE
    var upper = v + offset
    if AES_BLOCK_SIZE > JAVA_LONG_MAX_VALUE - upper:
        return JAVA_LONG_MAX_VALUE
    return upper + AES_BLOCK_SIZE


@export("ab3_adjusted_crypto_range")
def ab3_adjusted_crypto_range(start: Int, end: Int, out_addr: Int) abi("C") -> Int:
    """Write the aligned (start, end) a ranged CSE GetObject must fetch.

    `_get_adjusted_crypto_range`, which is a lower bound on the start and an
    upper bound on the end. Returns 0.
    """
    var o = lptr(out_addr)
    o[unsafe_offset=0] = ab3_cipher_block_lower_bound(start)
    o[unsafe_offset=1] = ab3_cipher_block_upper_bound(end)
    return 0


# ---------------------------------------------------------------------------
# GCM J0 derivation and CTR counter increment
# ---------------------------------------------------------------------------


@export("ab3_increment_blocks")
def ab3_increment_blocks(
    counter_addr: Int, block_delta: Int, out_addr: Int
) abi("C") -> Int:
    """Add `block_delta` to the big-endian 32-bit counter in bytes 12..15.

    `_increment_blocks`, whose upstream form repacks the last four bytes as a
    big-endian 64-bit integer; the result is identical because the top half of
    that integer is always zero. A zero delta is a no-op, as upstream. Returns
    0, or -1 when the delta does not fit in a signed 64-bit integer. `out` is
    always 16 bytes and receives a copy even on the error path.
    """
    var c = uptr(counter_addr)
    var d = uptr(out_addr)
    for k in range(16):
        d[unsafe_offset=k] = c[unsafe_offset=k]
    if block_delta == 0:
        return 0
    if Int64(block_delta) > JAVA_LONG_MAX_VALUE:
        return -1
    var carry = Int64(block_delta)
    var i = 15
    while i >= 12:
        var sum = Int64(d[unsafe_offset=i]) + (carry & 0xFF)
        d[unsafe_offset=Int64(i)] = UInt8(sum & 0xFF)
        carry = (carry >> 8) + (sum >> 8)
        i -= 1
    return 0


@export("ab3_compute_j0")
def ab3_compute_j0(iv_addr: Int, out_addr: Int) abi("C") -> Int:
    """Derive the GCM pre-counter block J0 from a 12-byte IV.

    `_compute_j0`: the IV, three zero bytes and a 0x01 block counter, then one
    increment so the first keystream block is skipped. Returns 0, or -1 when
    `iv_addr` is null (the length check lives in the caller, as upstream).
    """
    if iv_addr == 0:
        return -1
    var iv = uptr(iv_addr)
    var o = uptr(out_addr)
    for k in range(12):
        o[unsafe_offset=k] = iv[unsafe_offset=k]
    # 16 - 13 = 3 zero bytes, then the 0x01 block counter
    o[unsafe_offset=12] = 0
    o[unsafe_offset=13] = 0
    o[unsafe_offset=14] = 0
    o[unsafe_offset=15] = 1
    return ab3_increment_blocks(out_addr, 1, out_addr)


@export("ab3_adjust_iv_for_range")
def ab3_adjust_iv_for_range(
    iv_addr: Int, byte_offset: Int, out_addr: Int
) abi("C") -> Int:
    """Produce the CTR starting IV for a ranged decrypt.

    `_adjust_iv_for_range`: the block index is `byte_offset // 128`, which must
    be exact, and the counter block is J0 advanced by that many blocks. Returns
    0, -1 for a null IV and -2 for a misaligned offset.
    """
    var block_offset = Int64(byte_offset) // AES_BLOCK_SIZE
    if Int64(byte_offset) % AES_BLOCK_SIZE != 0:
        return -2
    if ab3_compute_j0(iv_addr, out_addr) != 0:
        return -1
    return ab3_increment_blocks(out_addr, Int(block_offset), out_addr)


# ---------------------------------------------------------------------------
# HTTP Range header parsing
# ---------------------------------------------------------------------------

# `RANGE_REGEX` is `bytes=(?P<start>\d+)-(?P<end>\d+)*`. out: start, end, has
# end, status. Status 0 is a match, 1 is no match, -1 is a start that does not
# fit in an Int64.


@export("ab3_parse_range_header")
def ab3_parse_range_header(buf_addr: Int, n: Int, out_addr: Int) abi("C") -> Int:
    """Parse an HTTP `Range` header value into (start, end, has_end).

    Returns 0 on a match, 1 when the value is not `bytes=<digits>[-<digits>]`,
    and -1 when the start overflows a 64-bit integer. An end offset that
    overflows saturates, which reproduces the 9223372036854775806 default that
    `S3CSE.get_object` substitutes for a missing end.
    """
    var p = uptr(buf_addr)
    var o = lptr(out_addr)
    o[unsafe_offset=0] = 0
    o[unsafe_offset=1] = -1
    o[unsafe_offset=2] = 0
    o[unsafe_offset=3] = 1
    if n < 6:
        return 1
    if p[unsafe_offset=0] != 98 or p[unsafe_offset=1] != 121 or p[unsafe_offset=2] != 116:
        return 1
    if p[unsafe_offset=3] != 101 or p[unsafe_offset=4] != 115:
        return 1
    if p[unsafe_offset=5] != 61:
        return 1
    var pos = 6
    var start = Int64(0)
    var digits = 0
    while pos < n and p[unsafe_offset=pos] >= 48 and p[unsafe_offset=pos] <= 57:
        var d = Int64(p[unsafe_offset=pos]) - 48
        if start > (JAVA_LONG_MAX_VALUE - d) // 10:
            return -1
        start = start * 10 + d
        digits += 1
        pos += 1
    if digits == 0:
        return 1
    if pos >= n or p[unsafe_offset=pos] != 45:
        return 1
    pos += 1
    var has_end = 0
    var end = Int64(0)
    var edigits = 0
    while pos < n and p[unsafe_offset=pos] >= 48 and p[unsafe_offset=pos] <= 57:
        var d = Int64(p[unsafe_offset=pos]) - 48
        if end <= (JAVA_LONG_MAX_VALUE - d) // 10:
            end = end * 10 + d
        else:
            end = JAVA_LONG_MAX_VALUE
        edigits += 1
        pos += 1
    if edigits > 0:
        has_end = 1
    # RANGE_REGEX is used with re.match, not fullmatch, so trailing bytes after
    # a well-formed prefix are ignored rather than rejected
    o[unsafe_offset=0] = start
    o[unsafe_offset=1] = end if has_end == 1 else -1
    o[unsafe_offset=2] = Int64(has_end)
    o[unsafe_offset=3] = 0
    return 0


# ---------------------------------------------------------------------------
# AEAD tag trimming for a ranged GCM decrypt
# ---------------------------------------------------------------------------


@export("ab3_trim_end")
def ab3_trim_end(
    desired_end: Int, entire_file_length: Int, aead_tag_len: Int
) abi("C") -> Int64:
    """Clamp a range end so it never reaches into the GCM authentication tag.

    The two lines from `_decrypt_v2`:
    `max_offset = entire_file_length - aead_tag_len - 1` and
    `desired_end = max_offset if desired_end > max_offset else desired_end`.
    """
    var max_offset = Int64(entire_file_length) - Int64(aead_tag_len) - 1
    var want = Int64(desired_end)
    if want > max_offset:
        return max_offset
    return want


# ---------------------------------------------------------------------------
# Batched forms
#
# The scalar kernels above do a handful of 64-bit operations per call, so a
# per-call ctypes transition costs far more than the arithmetic. A caller that
# is aligning a batch of ranges, or deriving the starting IV for a batch of
# ranged reads, should use these instead: one transition for the whole batch.
# ---------------------------------------------------------------------------


@export("ab3_adjusted_crypto_range_batch")
def ab3_adjusted_crypto_range_batch(
    starts_addr: Int, ends_addr: Int, n: Int, out_addr: Int
) abi("C") -> Int:
    """`ab3_adjusted_crypto_range` for `n` ranges; `out` holds 2n Int64.

    Returns 0.
    """
    var starts = lptr(starts_addr)
    var ends = lptr(ends_addr)
    var o = lptr(out_addr)
    for i in range(n):
        o[unsafe_offset=2 * i + 0] = ab3_cipher_block_lower_bound(
            Int(starts[unsafe_offset=i])
        )
        o[unsafe_offset=2 * i + 1] = ab3_cipher_block_upper_bound(
            Int(ends[unsafe_offset=i])
        )
    return 0


@export("ab3_adjust_iv_for_range_batch")
def ab3_adjust_iv_for_range_batch(
    ivs_addr: Int,
    n: Int,
    offsets_addr: Int,
    out_addr: Int,
    status_addr: Int,
) abi("C") -> Int:
    """`ab3_adjust_iv_for_range` for `n` 12-byte IVs laid out contiguously.

    `offsets` holds the byte offsets; `out` receives 16n bytes, one counter
    block per input, and `status` holds n codes (0 ok, -1 null IV, -2
    misaligned). Returns the number of entries that failed.
    """
    var ivs = uptr(ivs_addr)
    var offsets = lptr(offsets_addr)
    var o = uptr(out_addr)
    var status = lptr(status_addr)
    var bad = 0
    for i in range(n):
        var rc = ab3_adjust_iv_for_range(
            ivs_addr + 12 * i, Int(offsets[unsafe_offset=i]), out_addr + 16 * i
        )
        status[unsafe_offset=i] = Int64(rc)
        if rc != 0:
            bad += 1
    return bad
