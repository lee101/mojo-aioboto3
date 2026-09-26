# mojo-aioboto3

`mojo-aioboto3` is a Mojo port of the counter arithmetic inside
[aioboto3](https://aioboto3.readthedocs.io/)'s S3 client-side-encryption
layer.

**aioboto3 is glue, almost all of it.** `session.py`, `resources/`,
`dynamodb/table.py` and `s3/inject.py` are resource factories, event-hook
registration and parameter plumbing; they contain no arithmetic at all. The one
part of aioboto3 that does arithmetic of its own is `aioboto3/s3/cse.py`, and
even there the numeric band is narrow and well defined: the AES-CTR/GCM counter
block handling and the cipher-block range alignment that a ranged,
client-side-encrypted `GetObject` needs. That is what this project ports.

The Python package is `mojo_aioboto3`, so it installs alongside the real
`aioboto3` and the parity tests compare the two functions directly.

## Covered subset

| area | upstream source | ported API |
| --- | --- | --- |
| Cipher-block range alignment | `aioboto3/s3/cse.py` `_get_cipher_block_lower_bound`, `_get_cipher_block_upper_bound`, `_get_adjusted_crypto_range` | `cipher_block_lower_bound`, `cipher_block_upper_bound`, `adjusted_crypto_range`, `adjusted_crypto_range_batch` |
| GCM pre-counter block | `aioboto3/s3/cse.py` `_compute_j0` | `compute_j0` |
| CTR counter increment | `aioboto3/s3/cse.py` `_increment_blocks` | `increment_blocks` |
| Ranged CTR IV adjustment | `aioboto3/s3/cse.py` `_adjust_iv_for_range` | `adjust_iv_for_range`, `adjust_iv_for_range_batch` |
| `Range` header parsing | `aioboto3/s3/cse.py` `RANGE_REGEX` | `parse_range_header` |
| AEAD tag trimming | `aioboto3/s3/cse.py` `_decrypt_v2` | `trim_end` |

Every one of these is 64-bit or byte arithmetic. None of them approximates
anything, so the parity tests use exact equality, and a `ValueError` /
`RuntimeError` is asserted where the real function raises.

**Not implemented, and not attempted:** AES-CBC, AES-GCM, PKCS7 padding, the
key contexts (`SymmetricCryptoContext`, `AsymmetricCryptoContext`,
`KMSCryptoContext`, `MockKMSCryptoContext`), the `S3CSE` class itself, the S3
and KMS calls, the base64 and JSON metadata handling, the rest of `cse.py`, and
everything outside `cse.py`. Those are cryptography, I/O and string handling, and
they belong to the real `aioboto3`.

## Install

```bash
bash build/build.sh          # -> dist/libmojo-aioboto3.so
PYTHONPATH=python python -m pytest tests -q
```

The repository pins its own Mojo toolchain in `pixi.toml`
(`mojo = "==1.2.0.dev2026092605"`). Do not run `pixi install` in this tree; the
shared environment at `/nvme0n1-disk/mojo-toolchain` is the environment.

```python
import mojo_aioboto3 as mab

mab.adjusted_crypto_range(100, 200)      # (0, 384)
mab.compute_j0(iv)                      # 16-byte GCM pre-counter block
mab.adjust_iv_for_range(iv, 128 * 7)    # the CTR IV for a ranged decrypt
mab.parse_range_header(b"bytes=100-")   # (100, -1, False)
```

## Performance

Best-of-seven wall clock, same process, every case checked against the real
`aioboto3` function before timing.

| case | reference | mojo-aioboto3 | result |
| --- | ---: | ---: | ---: |
| `lower_bound`, one call each, n=65536 | 51.27 ms | 104.45 ms | **0.49x, a slowdown** |
| `adjusted_crypto_range`, one call each, n=65536 | 112.28 ms | 664.29 ms | **0.17x, a slowdown** |
| `adjusted_crypto_range_batch`, n=65536 | 184.33 ms | 0.55 ms | 338x faster |
| `adjust_iv_for_range_batch`, n=16384 | 120.64 ms | 21.26 ms | 5.67x faster |
| `increment_blocks`, one call each, n=32768 | 123.85 ms | 513.77 ms | **0.24x, a slowdown** |
| `increment_blocks`, kernel calls only, n=32768 | 118.89 ms | 95.86 ms | 1.24x faster |
| `parse_range_header`, one call each, n=16384 | 36.24 ms | 263.83 ms | **0.14x, a slowdown** |

The one-call-per-row rows lose, and the reason is worth stating plainly rather
than hiding behind a batched number: `aioboto3`'s CSE arithmetic is a handful of
integer operations per request — one modulo, one subtraction, one shift. There
is no inner loop to speed up. Crossing the FFI costs about a microsecond, so a
per-call port of a two-operation function is strictly slower than the Python,
and no amount of kernel tuning changes that. The `increment_blocks kernel` row
isolates the transition: with the Python-side buffer plumbing removed the
kernel is only 1.24x the real function, which is the honest ceiling for work
this small.

The batched rows are the point of the port. `adjusted_crypto_range_batch` and
`adjust_iv_for_range_batch` do one transition for the whole batch, and there the
Mojo kernel is 338x and 5.7x faster. A caller that has a list of ranges to align
— a manifest walk, a multipart upload plan, a batch of presigned range URLs —
should use those, and the README says which to reach for.

Reproduce with:

```bash
python bench/bench.py
```

## How it works

All kernels live in `src/kernels.mojo`, one compilation unit, because shared
library build cost is largely fixed. `build/build.sh` compiles it with
`mojo build --emit shared-lib` into `dist/libmojo-aioboto3.so`.

The `python/mojo_aioboto3` layer owns every array. Buffers cross the C ABI as
64-bit addresses (`ctypes.c_int64`; `c_int` truncates them and segfaults) and
are reconstructed in Mojo as pointers, which keeps the exported symbols
non-parametric.

Three details are load-bearing and each has a test that fails without it:

- `ab3_cipher_block_upper_bound` saturates **before** each addition. The
  upstream expression `value + (128 - value % 128) + 128` is what the Java port
  did, and evaluating it naively at offsets near `Long.MAX_VALUE` wraps
  negative. `test_upper_bound_saturates_at_the_java_long_maximum` pins it.
- `RANGE_REGEX` is used with `re.match`, not `fullmatch`, so `bytes=1-2-3` and
  `bytes=1-2 ` both match the prefix `bytes=1-2` and the rest is ignored. A
  kernel that demanded a full-buffer match would reject inputs upstream accepts.
- An absent end offset is reported as -1, not 0, because `S3CSE.get_object`
  substitutes `9223372036854775806` for it; conflating the two would make
  `bytes=0-` look like the range `[0, 0]`.

## Tests

122 parity tests against `aioboto3.s3.cse`, all exact:

- both block-bound functions at 18 offsets each, plus the `Long.MAX_VALUE`
  saturation and the guarantee that the adjusted range contains the request and
  is block-aligned;
- `compute_j0` at six IVs plus its byte layout, `increment_blocks` at nine
  deltas including a full carry across the 4-byte field, a zero-delta copy and
  an overflow that must raise;
- `adjust_iv_for_range` at eight block indices, its equivalence to
  `increment_blocks(compute_j0(iv), blocks)`, and every misaligned offset in
  `[0, 129)`;
- nine `Range` headers against `RANGE_REGEX`, eleven rejected forms, the
  overflowing-start and overflowing-end cases, and the trailing-bytes behaviour;
- `trim_end` at seven (end, length, tag) triples plus a case that separates the
  tag length from the 16-byte AEAD tag default;
- the batched forms against both the scalar form and the real functions,
  including that one misaligned entry does not corrupt its neighbours.

## License

MIT
