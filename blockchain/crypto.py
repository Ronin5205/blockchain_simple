"""Key material and signing primitives.

This is the only module that touches the `cryptography` package. Accounts are
identified by the hex of their compressed SECP256K1 public key.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP256K1()
PUBLIC_KEY_HEX_LEN = 66  # 33-byte compressed point


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(CURVE)


def save_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    """Write an unencrypted PEM. Demo only -- see README."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def load_key(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError(f"{path} is not an elliptic-curve private key")
    return key


def public_key_hex(key: ec.EllipticCurvePrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        .hex()
    )


def sign(key: ec.EllipticCurvePrivateKey, payload: bytes) -> str:
    return key.sign(payload, ec.ECDSA(hashes.SHA256())).hex()


def verify(public_key_hex_: str, payload: bytes, signature_hex: str) -> bool:
    """Never raises: a malformed key or signature is simply not a valid one."""
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            CURVE, bytes.fromhex(public_key_hex_)
        )
        public_key.verify(
            bytes.fromhex(signature_hex), payload, ec.ECDSA(hashes.SHA256())
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def canonical_json(obj: object) -> bytes:
    """The one deterministic encoding used for both hashing and signing.

    Any drift here silently invalidates every hash and signature, so both
    blocks and transactions go through this single function.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
