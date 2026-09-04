"""Rule-by-rule checks on the chain. Difficulty is lowered so mining is fast."""

import json
import tempfile
import unittest
from pathlib import Path

from blockchain.chain import Blockchain, InvalidChain, InvalidTransaction
from blockchain.crypto import generate_private_key, public_key_hex
from blockchain.transaction import Transaction

DIFFICULTY = 1
REWARD = 50


def new_chain() -> Blockchain:
    return Blockchain(difficulty=DIFFICULTY, reward=REWARD)


class ChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alice = generate_private_key()
        self.bob = generate_private_key()
        self.alice_pk = public_key_hex(self.alice)
        self.bob_pk = public_key_hex(self.bob)
        self.chain = new_chain()

    def fund_alice(self) -> None:
        self.chain.mine_block(self.alice_pk)

    def test_mined_chain_validates_and_pays_the_reward(self):
        self.fund_alice()
        self.assertIsNone(self.chain.validate())
        self.assertEqual(self.chain.balance_of(self.alice_pk), REWARD)

    def test_transfer_moves_value_once_mined(self):
        self.fund_alice()
        self.chain.add_transaction(
            Transaction.create_signed(self.alice, self.bob_pk, 30)
        )
        self.assertEqual(self.chain.balance_of(self.bob_pk), 0, "not yet confirmed")
        self.chain.mine_block(self.alice_pk)
        self.assertIsNone(self.chain.validate())
        self.assertEqual(self.chain.balance_of(self.bob_pk), 30)
        self.assertEqual(self.chain.balance_of(self.alice_pk), 2 * REWARD - 30)

    def test_proof_of_work_target_is_met(self):
        block = self.fund_alice() or self.chain.chain[-1]
        self.assertTrue(block.hash().startswith("0" * DIFFICULTY))

    def test_tampering_with_an_amount_breaks_validation(self):
        self.fund_alice()
        self.chain.add_transaction(
            Transaction.create_signed(self.alice, self.bob_pk, 10)
        )
        self.chain.mine_block(self.alice_pk)
        block = self.chain.chain[-1]
        block.transactions[1].amount = 1_000_000
        self.assertIn("proof-of-work", self.chain.validate(), "hash must change")
        block.mine(DIFFICULTY)  # re-seal it; the signature is the real backstop
        self.assertIn("invalid signature", self.chain.validate())

    def test_tampering_with_a_link_breaks_validation(self):
        self.fund_alice()
        self.chain.mine_block(self.alice_pk)
        self.chain.chain[1].nonce += 1  # changes block 1's hash
        failure = self.chain.validate()
        self.assertTrue(
            "proof-of-work" in failure or "does not link" in failure, failure
        )

    def test_signature_by_the_wrong_key_is_rejected(self):
        self.fund_alice()
        forged = Transaction.create_signed(self.bob, self.bob_pk, 10)
        forged.sender = self.alice_pk  # claim alice's funds with bob's signature
        with self.assertRaises(InvalidTransaction) as ctx:
            self.chain.add_transaction(forged)
        self.assertIn("signature", str(ctx.exception))

    def test_unsigned_transaction_is_rejected(self):
        self.fund_alice()
        tx = Transaction.create_signed(self.alice, self.bob_pk, 10)
        tx.signature = None
        with self.assertRaises(InvalidTransaction):
            self.chain.add_transaction(tx)

    def test_overdraft_is_rejected(self):
        self.fund_alice()
        with self.assertRaises(InvalidTransaction) as ctx:
            self.chain.add_transaction(
                Transaction.create_signed(self.alice, self.bob_pk, REWARD + 1)
            )
        self.assertIn("insufficient funds", str(ctx.exception))

    def test_pending_transactions_cannot_double_spend(self):
        self.fund_alice()
        self.chain.add_transaction(
            Transaction.create_signed(self.alice, self.bob_pk, 40)
        )
        with self.assertRaises(InvalidTransaction):
            self.chain.add_transaction(
                Transaction.create_signed(self.alice, self.bob_pk, 40)
            )

    def test_replaying_a_transaction_is_rejected(self):
        self.fund_alice()
        tx = Transaction.create_signed(self.alice, self.bob_pk, 10)
        self.chain.add_transaction(tx)
        self.chain.mine_block(self.alice_pk)
        with self.assertRaises(InvalidTransaction) as ctx:
            self.chain.add_transaction(tx)
        self.assertIn("replay", str(ctx.exception))

    def test_user_cannot_mint_a_coinbase(self):
        with self.assertRaises(InvalidTransaction):
            self.chain.add_transaction(Transaction.coinbase(self.alice_pk, REWARD))

    def test_inflated_coinbase_breaks_validation(self):
        self.fund_alice()
        block = self.chain.chain[-1]
        block.transactions[0].amount = REWARD * 10
        block.mine(DIFFICULTY)  # re-seal it: the proof is not what catches this
        self.assertIn("coinbase", self.chain.validate())

    def test_zero_and_negative_amounts_are_rejected(self):
        self.fund_alice()
        for amount in (0, -5):
            with self.subTest(amount=amount):
                with self.assertRaises(InvalidTransaction):
                    self.chain.add_transaction(
                        Transaction.create_signed(self.alice, self.bob_pk, amount)
                    )


class PersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "chain.json"
        self.alice = generate_private_key()
        self.bob = generate_private_key()
        self.chain = new_chain()
        self.chain.mine_block(public_key_hex(self.alice))
        self.chain.add_transaction(
            Transaction.create_signed(self.alice, public_key_hex(self.bob), 25)
        )
        self.chain.save(self.path)

    def load(self) -> Blockchain:
        return Blockchain.load(self.path, difficulty=DIFFICULTY, reward=REWARD)

    def test_round_trip_preserves_chain_and_mempool(self):
        loaded = self.load()
        self.assertEqual(len(loaded.chain), len(self.chain.chain))
        self.assertEqual(len(loaded.pending), 1)
        self.assertEqual(loaded.balances(), self.chain.balances())
        self.assertEqual(
            [b.hash() for b in loaded.chain], [b.hash() for b in self.chain.chain]
        )

    def test_corrupted_chain_file_is_refused(self):
        data = json.loads(self.path.read_text())
        data["chain"][1]["transactions"][0]["amount"] = 999
        self.path.write_text(json.dumps(data))
        with self.assertRaises(InvalidChain):
            self.load()

    def test_unparseable_chain_file_is_refused(self):
        self.path.write_text("{not json")
        with self.assertRaises(InvalidChain):
            self.load()

    def test_unknown_fields_are_refused(self):
        data = json.loads(self.path.read_text())
        data["chain"][0]["surprise"] = True
        self.path.write_text(json.dumps(data))
        with self.assertRaises(InvalidChain):
            self.load()


if __name__ == "__main__":
    unittest.main()
