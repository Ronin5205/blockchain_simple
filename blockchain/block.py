"""Blocks: the hashed, proof-of-work-sealed container for transactions."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .crypto import canonical_json, sha256_hex
from .transaction import Transaction

_FIELDS = ("index", "timestamp", "previous_hash", "nonce", "transactions")


@dataclass
class Block:
    index: int
    previous_hash: str
    transactions: list[Transaction]
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0

    def hash(self) -> str:
        """SHA-256 over every field of the block, transactions included."""
        return sha256_hex(
            canonical_json(
                {
                    "index": self.index,
                    "timestamp": self.timestamp,
                    "previous_hash": self.previous_hash,
                    "nonce": self.nonce,
                    "transactions": [tx.to_dict() for tx in self.transactions],
                }
            )
        )

    def has_valid_proof(self, difficulty: int) -> bool:
        return self.hash().startswith("0" * difficulty)

    def mine(self, difficulty: int) -> str:
        while not self.has_valid_proof(difficulty):
            self.nonce += 1
        return self.hash()

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

    @classmethod
    def from_dict(cls, data: object) -> "Block":
        if not isinstance(data, dict) or set(data) != set(_FIELDS):
            raise ValueError(f"block must have exactly the fields {_FIELDS}")
        if not isinstance(data["transactions"], list):
            raise ValueError("block transactions must be a list")
        return cls(
            index=data["index"],
            timestamp=data["timestamp"],
            previous_hash=data["previous_hash"],
            nonce=data["nonce"],
            transactions=[Transaction.from_dict(t) for t in data["transactions"]],
        )
