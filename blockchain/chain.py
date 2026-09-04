"""The chain itself: mempool admission, mining, validation and persistence.

Every rule that makes the ledger trustworthy is enforced in `validate()`, which
replays the whole chain from genesis. `add_transaction` applies the same rules
early so bad transactions never reach a block, but `validate()` is the
authority -- it is what a loaded `chain.json` must survive.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .block import Block
from .transaction import Transaction

DIFFICULTY = 4
REWARD = 50
GENESIS_PREVIOUS_HASH = "0" * 64
GENESIS_TIMESTAMP = 0.0


class InvalidTransaction(ValueError):
    """A transaction that may not enter the mempool."""


class InvalidChain(ValueError):
    """A stored chain that failed validation."""


@dataclass
class Blockchain:
    # difficulty and reward are constructor arguments so tests can mine cheaply;
    # they are properties of this node, not of the stored file.
    difficulty: int = DIFFICULTY
    reward: int = REWARD
    chain: list[Block] = field(default_factory=list)
    pending: list[Transaction] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.chain:
            self.chain.append(self._genesis())

    def _genesis(self) -> Block:
        """Fixed content, so every node at the same difficulty agrees on it."""
        block = Block(
            index=0,
            previous_hash=GENESIS_PREVIOUS_HASH,
            transactions=[],
            timestamp=GENESIS_TIMESTAMP,
        )
        block.mine(self.difficulty)
        return block

    # -- mempool ----------------------------------------------------------

    def add_transaction(self, tx: Transaction) -> None:
        if tx.is_coinbase:
            raise InvalidTransaction("only mining may create a coinbase transaction")
        if not tx.is_well_formed():
            raise InvalidTransaction("malformed transaction")
        if not tx.is_signature_valid():
            raise InvalidTransaction("signature does not match sender")
        if tx.tx_id() in self._known_tx_ids():
            raise InvalidTransaction("transaction already seen (replay)")

        available = self.balance_of(tx.sender) - sum(
            p.amount for p in self.pending if p.sender == tx.sender
        )
        if available < tx.amount:
            raise InvalidTransaction(
                f"insufficient funds: {available} available, {tx.amount} requested"
            )
        self.pending.append(tx)

    def _known_tx_ids(self) -> set[str]:
        ids = {tx.tx_id() for block in self.chain for tx in block.transactions}
        ids.update(tx.tx_id() for tx in self.pending)
        return ids

    # -- mining -----------------------------------------------------------

    def mine_block(self, miner: str) -> Block:
        block = Block(
            index=len(self.chain),
            previous_hash=self.chain[-1].hash(),
            transactions=[Transaction.coinbase(miner, self.reward), *self.pending],
        )
        block.mine(self.difficulty)
        self.chain.append(block)
        self.pending = []
        return block

    # -- balances ---------------------------------------------------------

    def balances(self) -> dict[str, int]:
        balances: dict[str, int] = {}
        for block in self.chain:
            for tx in block.transactions:
                _apply(balances, tx)
        return balances

    def balance_of(self, public_key: str) -> int:
        return self.balances().get(public_key, 0)

    # -- validation -------------------------------------------------------

    def validate(self) -> str | None:
        """Return the first violated rule, or None if the whole state holds."""
        if not self.chain:
            return "chain is empty"

        genesis = self.chain[0]
        if genesis.previous_hash != GENESIS_PREVIOUS_HASH or genesis.transactions:
            return "block 0 is not a valid genesis block"

        balances: dict[str, int] = {}
        seen_tx_ids: set[str] = set()

        for i, block in enumerate(self.chain):
            if block.index != i:
                return f"block {i} claims index {block.index}"
            if i > 0 and block.previous_hash != self.chain[i - 1].hash():
                return f"block {i} does not link to block {i - 1}"
            if not block.has_valid_proof(self.difficulty):
                return f"block {i} fails the proof-of-work target"
            if i > 0 and not block.transactions:
                return f"block {i} has no coinbase transaction"

            for position, tx in enumerate(block.transactions):
                if tx.is_coinbase != (position == 0):
                    return f"block {i} transaction {position} misplaces the coinbase"
                if not tx.is_well_formed():
                    return f"block {i} transaction {position} is malformed"
                if not tx.is_signature_valid():
                    return f"block {i} transaction {position} has an invalid signature"
                if tx.tx_id() in seen_tx_ids:
                    return f"block {i} transaction {position} is a replay"
                seen_tx_ids.add(tx.tx_id())
                if tx.is_coinbase:
                    if tx.amount != self.reward:
                        return (
                            f"block {i} pays a coinbase of {tx.amount}, "
                            f"expected {self.reward}"
                        )
                elif balances.get(tx.sender, 0) < tx.amount:
                    return f"block {i} transaction {position} overdraws its sender"
                _apply(balances, tx)

        return self._validate_pending(balances, seen_tx_ids)

    def _validate_pending(
        self, balances: dict[str, int], seen_tx_ids: set[str]
    ) -> str | None:
        spent: dict[str, int] = {}
        for position, tx in enumerate(self.pending):
            if tx.is_coinbase:
                return f"pending transaction {position} is a coinbase"
            if not tx.is_well_formed():
                return f"pending transaction {position} is malformed"
            if not tx.is_signature_valid():
                return f"pending transaction {position} has an invalid signature"
            if tx.tx_id() in seen_tx_ids:
                return f"pending transaction {position} is a replay"
            seen_tx_ids.add(tx.tx_id())
            spent[tx.sender] = spent.get(tx.sender, 0) + tx.amount
            if balances.get(tx.sender, 0) < spent[tx.sender]:
                return f"pending transaction {position} overdraws its sender"
        return None

    # -- persistence ------------------------------------------------------

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "chain": [b.to_dict() for b in self.chain],
                    "pending": [t.to_dict() for t in self.pending],
                },
                indent=2,
            )
        )

    @classmethod
    def load(
        cls, path: Path, difficulty: int = DIFFICULTY, reward: int = REWARD
    ) -> "Blockchain":
        """Read a chain file. It is untrusted input, so it must validate."""
        try:
            data = json.loads(path.read_text())
            if not isinstance(data, dict) or set(data) != {"chain", "pending"}:
                raise ValueError("file must hold a chain and a pending list")
            if not isinstance(data["chain"], list) or not isinstance(
                data["pending"], list
            ):
                raise ValueError("chain and pending must both be lists")
            chain = cls(
                difficulty=difficulty,
                reward=reward,
                chain=[Block.from_dict(b) for b in data["chain"]],
                pending=[Transaction.from_dict(t) for t in data["pending"]],
            )
        except (ValueError, TypeError) as exc:
            raise InvalidChain(f"{path} is not a readable chain: {exc}") from exc

        failure = chain.validate()
        if failure:
            raise InvalidChain(f"{path} is invalid: {failure}")
        return chain

    @classmethod
    def load_or_create(
        cls, path: Path, difficulty: int = DIFFICULTY, reward: int = REWARD
    ) -> "Blockchain":
        if path.exists():
            return cls.load(path, difficulty=difficulty, reward=reward)
        return cls(difficulty=difficulty, reward=reward)


def _apply(balances: dict[str, int], tx: Transaction) -> None:
    if not tx.is_coinbase:
        balances[tx.sender] = balances.get(tx.sender, 0) - tx.amount
    balances[tx.recipient] = balances.get(tx.recipient, 0) + tx.amount
