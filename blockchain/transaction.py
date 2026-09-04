"""Transactions and their spend-authorization rules."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from .crypto import (
    PUBLIC_KEY_HEX_LEN,
    canonical_json,
    public_key_hex,
    sha256_hex,
    sign,
    verify,
)

_FIELDS = ("sender", "recipient", "amount", "nonce", "signature")


@dataclass
class Transaction:
    """A value transfer. `sender is None` marks the block's coinbase reward.

    Identities are compressed-public-key hex; there is no separate address.
    """

    sender: str | None
    recipient: str
    amount: int
    nonce: str
    signature: str | None = None

    @classmethod
    def create_signed(
        cls, key: ec.EllipticCurvePrivateKey, recipient: str, amount: int
    ) -> "Transaction":
        tx = cls(
            sender=public_key_hex(key),
            recipient=recipient,
            amount=amount,
            nonce=secrets.token_hex(8),
        )
        tx.signature = sign(key, tx.canonical_payload())
        return tx

    @classmethod
    def coinbase(cls, recipient: str, amount: int) -> "Transaction":
        return cls(
            sender=None, recipient=recipient, amount=amount, nonce=secrets.token_hex(8)
        )

    @property
    def is_coinbase(self) -> bool:
        return self.sender is None

    def canonical_payload(self) -> bytes:
        """The signed bytes -- everything but the signature itself.

        ECDSA signatures are non-deterministic, so they must stay out of both
        the signed payload and the transaction id.
        """
        return canonical_json(
            {
                "sender": self.sender,
                "recipient": self.recipient,
                "amount": self.amount,
                "nonce": self.nonce,
            }
        )

    def tx_id(self) -> str:
        return sha256_hex(self.canonical_payload())

    def is_signature_valid(self) -> bool:
        if self.is_coinbase:
            return self.signature is None
        if not self.signature:
            return False
        return verify(self.sender, self.canonical_payload(), self.signature)

    def is_well_formed(self) -> bool:
        return (
            isinstance(self.amount, int)
            and not isinstance(self.amount, bool)
            and self.amount > 0
            and isinstance(self.recipient, str)
            and len(self.recipient) == PUBLIC_KEY_HEX_LEN
            and isinstance(self.nonce, str)
            and bool(self.nonce)
            and (self.is_coinbase or len(self.sender) == PUBLIC_KEY_HEX_LEN)
        )

    def to_dict(self) -> dict:
        return {f: getattr(self, f) for f in _FIELDS}

    @classmethod
    def from_dict(cls, data: object) -> "Transaction":
        if not isinstance(data, dict) or set(data) != set(_FIELDS):
            raise ValueError(f"transaction must have exactly the fields {_FIELDS}")
        return cls(**data)

    def summary(self) -> str:
        source = "COINBASE" if self.is_coinbase else self.sender[:12]
        return f"{source} -> {self.recipient[:12]} : {self.amount}"
