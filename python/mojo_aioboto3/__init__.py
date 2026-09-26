"""mojo-aioboto3: the counter arithmetic behind aioboto3's S3 client-side encryption.

aioboto3 is a thin wrapper around boto3 -- session construction, resource
factories, DynamoDB tables, S3 parameter injection. None of that is numeric and
none of it is ported. The one part of aioboto3 that does arithmetic of its own is
`aioboto3/s3/cse.py`, and within it the arithmetic is exactly the AES-CTR/GCM
counter block handling and the cipher-block range alignment that a ranged,
client-side-encrypted GetObject needs. That is what this package implements.

Installable alongside the real `aioboto3`, which the parity tests compare
against directly.
"""

from ._lib import (
    AES_BLOCK_SIZE,
    JAVA_LONG_MAX_VALUE,
    OPEN_ENDED_DEFAULT,
    adjusted_crypto_range,
    adjusted_crypto_range_batch,
    adjust_iv_for_range,
    adjust_iv_for_range_batch,
    cipher_block_lower_bound,
    cipher_block_upper_bound,
    compute_j0,
    increment_blocks,
    parse_range_header,
    trim_end,
)

__all__ = [
    "adjusted_crypto_range",
    "adjusted_crypto_range_batch",
    "adjust_iv_for_range",
    "adjust_iv_for_range_batch",
    "cipher_block_lower_bound",
    "cipher_block_upper_bound",
    "compute_j0",
    "increment_blocks",
    "parse_range_header",
    "trim_end",
    "AES_BLOCK_SIZE",
    "JAVA_LONG_MAX_VALUE",
    "OPEN_ENDED_DEFAULT",
]
__version__ = "0.1.0"
