import os
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "python"))

_LIB = _ROOT / "dist" / "libmojo-aioboto3.so"

if not _LIB.exists():
    pytest.skip(
        "libmojo-aioboto3.so not built; run `bash build/build.sh`",
        allow_module_level=True,
    )


# ---------------------------------------------------------------------------
# The real aioboto3 functions, imported directly so the parity tests compare
# against the code they replace.
# ---------------------------------------------------------------------------


def cse():
    """Import `aioboto3.s3.cse` on demand; it pulls in `cryptography`."""
    import aioboto3.s3.cse as mod

    return mod


def real_range(value: str):
    """`RANGE_REGEX` + the end-offset defaulting `S3CSE.get_object` does."""
    mod = cse()
    m = mod.RANGE_REGEX.match(value)
    if not m:
        raise ValueError(f"Dont understand this range value {value}")
    start = int(m.group(1))
    raw_end = m.group(2)
    end = mod.JAVA_LONG_MAX_VALUE - 1 if raw_end is None else int(raw_end)
    return start, end
