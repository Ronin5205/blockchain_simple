"""Command line front end.

Wallet *names* exist only here, as a convenience for typing. The chain itself
only ever knows public keys.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .chain import Blockchain, InvalidChain, InvalidTransaction
from .crypto import (
    PUBLIC_KEY_HEX_LEN,
    generate_private_key,
    load_key,
    public_key_hex,
    save_key,
)
from .transaction import Transaction


def _wallet_path(data_dir: Path, name: str) -> Path:
    return data_dir / "wallets" / f"{name}.pem"


def _chain_path(data_dir: Path) -> Path:
    return data_dir / "chain.json"


def _resolve(data_dir: Path, identity: str) -> str:
    """Turn a wallet name or a raw public key into a public key."""
    path = _wallet_path(data_dir, identity)
    if path.exists():
        return public_key_hex(load_key(path))
    if len(identity) == PUBLIC_KEY_HEX_LEN:
        try:
            bytes.fromhex(identity)
        except ValueError:
            pass
        else:
            return identity
    raise SystemExit(f"unknown wallet or public key: {identity}")


def _load_key(data_dir: Path, name: str):
    path = _wallet_path(data_dir, name)
    if not path.exists():
        raise SystemExit(f"no wallet named {name!r}; create one with: keygen {name}")
    return load_key(path)


def _load_chain(data_dir: Path) -> Blockchain:
    try:
        return Blockchain.load_or_create(_chain_path(data_dir))
    except InvalidChain as exc:
        raise SystemExit(str(exc)) from exc


def cmd_keygen(args: argparse.Namespace) -> None:
    path = _wallet_path(args.data_dir, args.name)
    if path.exists():
        raise SystemExit(f"wallet {args.name!r} already exists at {path}")
    key = generate_private_key()
    save_key(path, key)
    print(f"created wallet {args.name!r} at {path}")
    print(f"public key: {public_key_hex(key)}")


def cmd_send(args: argparse.Namespace) -> None:
    chain = _load_chain(args.data_dir)
    key = _load_key(args.data_dir, getattr(args, "from"))
    recipient = _resolve(args.data_dir, args.to)
    tx = Transaction.create_signed(key, recipient, args.amount)
    try:
        chain.add_transaction(tx)
    except InvalidTransaction as exc:
        raise SystemExit(f"rejected: {exc}") from exc
    chain.save(_chain_path(args.data_dir))
    print(f"queued {tx.summary()}  (id {tx.tx_id()[:16]})")
    print(f"{len(chain.pending)} transaction(s) pending; run `mine` to confirm")


def cmd_mine(args: argparse.Namespace) -> None:
    chain = _load_chain(args.data_dir)
    miner = _resolve(args.data_dir, args.wallet)
    confirmed = len(chain.pending)
    block = chain.mine_block(miner)
    chain.save(_chain_path(args.data_dir))
    print(f"mined block {block.index} with nonce {block.nonce}")
    print(f"  hash: {block.hash()}")
    print(f"  confirmed {confirmed} transaction(s) + {chain.reward} coinbase to miner")


def cmd_balance(args: argparse.Namespace) -> None:
    chain = _load_chain(args.data_dir)
    if args.who:
        who = _resolve(args.data_dir, args.who)
        print(f"{who[:16]}...  {chain.balance_of(who)}")
        return
    balances = chain.balances()
    if not balances:
        print("no balances yet -- mine a block first")
        return
    names = {
        public_key_hex(load_key(p)): p.stem
        for p in sorted((args.data_dir / "wallets").glob("*.pem"))
    }
    for key, amount in sorted(balances.items(), key=lambda kv: -kv[1]):
        print(f"{names.get(key, key[:16] + '...'):<20} {amount}")


def cmd_show(args: argparse.Namespace) -> None:
    chain = _load_chain(args.data_dir)
    for block in chain.chain:
        print(f"block {block.index}  nonce {block.nonce}")
        print(f"  hash: {block.hash()}")
        print(f"  prev: {block.previous_hash}")
        for tx in block.transactions:
            print(f"    {tx.summary()}")
    if chain.pending:
        print(f"pending ({len(chain.pending)}):")
        for tx in chain.pending:
            print(f"    {tx.summary()}")


def cmd_validate(args: argparse.Namespace) -> None:
    path = _chain_path(args.data_dir)
    if not path.exists():
        raise SystemExit(f"no chain at {path}")
    try:
        Blockchain.load(path)
    except InvalidChain as exc:
        raise SystemExit(f"INVALID: {exc}") from exc
    print("OK")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blockchain", description="A small proof-of-work blockchain."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("."),
        help="where chain.json and wallets/ live (default: current directory)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="create a new wallet")
    keygen.add_argument("name")
    keygen.set_defaults(func=cmd_keygen)

    send = sub.add_parser("send", help="sign a transaction into the mempool")
    send.add_argument("--from", required=True, help="wallet name that pays")
    send.add_argument("--to", required=True, help="wallet name or public key")
    send.add_argument("--amount", type=int, required=True)
    send.set_defaults(func=cmd_send)

    mine = sub.add_parser("mine", help="mine the pending transactions into a block")
    mine.add_argument("--wallet", required=True, help="wallet that receives the reward")
    mine.set_defaults(func=cmd_mine)

    balance = sub.add_parser("balance", help="show balances")
    balance.add_argument("who", nargs="?", help="wallet name or public key")
    balance.set_defaults(func=cmd_balance)

    sub.add_parser("show", help="print the chain").set_defaults(func=cmd_show)
    sub.add_parser("validate", help="re-check every rule").set_defaults(
        func=cmd_validate
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    args.func(args)
    return 0
