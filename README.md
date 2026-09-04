# A simple blockchain

A small but complete proof-of-work blockchain: SHA-256 block linking, mining, a
mempool, ECDSA-signed transactions with real spend authorization, and full-chain
validation — driven from a CLI.

Requires Python 3.12 and the `cryptography` package (already present on this
machine). Nothing else to install.

## Quickstart

```bash
python main.py keygen alice
python main.py keygen bob
python main.py mine --wallet alice          # alice earns the 50 coinbase
python main.py send --from alice --to bob --amount 30
python main.py mine --wallet alice
python main.py balance                      # alice 70, bob 30
python main.py validate                     # OK
```

State lives in `chain.json` and `wallets/<name>.pem` in the current directory;
`--data-dir` puts them elsewhere. `python main.py show` prints the chain.

Try breaking it: edit an `amount` inside `chain.json` and re-run `validate`. It
names the rule that broke, and every command that reads the chain refuses to
load it.

```bash
python -m unittest discover -s tests -t .
```

## How it works

Accounts *are* keys: an identity is the hex of a compressed SECP256K1 public key,
and a wallet name is only a CLI convenience. Balances are account-based, folded
over the chain — not UTXOs.

`Blockchain.validate()` (`blockchain/chain.py`) is the authority. It replays the
chain from genesis and enforces:

1. A block's hash covers all of its fields, including its transactions.
2. Each block links to the previous one by hash, and indexes are contiguous.
3. Every block's hash meets the difficulty target (4 leading zeros).
4. Every non-coinbase transaction carries a signature over its canonical payload,
   valid under the sender's public key.
5. Exactly one coinbase per block, at position 0, unsigned, paying exactly 50.
6. No sender ever goes negative, counting earlier transactions in the same block.
7. No transaction id (SHA-256 of its payload, which includes a random nonce)
   appears twice — so a signed transaction cannot be replayed.
8. `chain.json` is untrusted input: it is validated in full on load, and a bad
   file is an error rather than a silently accepted chain.

`add_transaction` applies the same rules at mempool admission so bad transactions
never reach a block, but `validate()` is what a stored chain has to survive.

Signatures cover everything but the signature itself — ECDSA is
non-deterministic, so including it would make ids and payloads unstable.

## Not included

Deliberately out of scope: peer-to-peer networking, longest-chain consensus
across nodes, an HTTP API, UTXOs, Merkle trees, difficulty retargeting, and
transaction fees. This is a single-node ledger.

## Security caveat

**Private keys are stored unencrypted** under `wallets/`. That is fine for a
local demo and unacceptable for anything holding real value — passing a
passphrase to `save_key`/`load_key` in `blockchain/crypto.py` is the fix if this
ever grows up.
