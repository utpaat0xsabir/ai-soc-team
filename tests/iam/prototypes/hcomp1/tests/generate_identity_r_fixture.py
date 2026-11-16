#!/usr/bin/env python3
"""Reproduce a public, synthetic identity-R fixture using only Python's stdlib."""

import hashlib
from pathlib import Path

L = 2**252 + 27742317777372353535851937790883648493
IDENTITY_R = bytes([1]) + bytes(31)
BASEPOINT = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
MESSAGE = b"H-COMP-1 synthetic identity-R fixture v1"


def main() -> None:
    # With A=B and r=0, the Ed25519 equation S*B = R + k*A holds for S=k.
    scalar = int.from_bytes(hashlib.sha512(IDENTITY_R + BASEPOINT + MESSAGE).digest(), "little") % L
    assert 0 < scalar < L - 1
    signature = IDENTITY_R + scalar.to_bytes(32, "little")
    line = "\t".join(("synthetic-identity-r-v1", MESSAGE.hex(), BASEPOINT.hex(), signature.hex(), "ACCEPT"))
    destination = Path(__file__).with_name("identity-r-positive.tsv")
    destination.write_text(line + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
