# Transaction-source deanonymization of Bitcoin nodes

Can a network observer link an on-chain address to the node whose wallet tracks it? Yes — actively and
cheaply. Plant a low-fee payment to the address; the Bitcoin Core wallet watching it rebroadcasts the
stuck tx to all peers on its 12-36h timer, and a freshly connected spy sees which node announces it.
100% attribution on regtest for a few tens of sats per target. Watch-only and hot Core wallets are both
affected; private broadcast and being behind NAT don't help.

We also measured topology leakage on a Hyperion simulator (the second announcer is a direct neighbour of
the source ~90% of the time, but timing can't rank the wider neighbourhood). All experiments ran on
regtest and a simulator — nothing was measured on mainnet.

## Read
- [reports/deanonymization.md](reports/deanonymization.md) — the write-up: attack, cost, affected
  software, clustering, the multi-network leak, the topology measurement, and mitigations.
- [lab/RESULTS.md](lab/RESULTS.md) — raw lab method and numbers.

## Code
- `lab/` — Docker + regtest/signet lab (rebroadcast attribution, NAT capture, fingerprinting).
- `src/` — live-network first-spy observers and the P2P handshake library; `make_anim.py` builds the figures.

## Sensitive data
The observers produce per-transaction `txid -> source-IP` tables — the deanonymization itself. These are
gitignored (`data/observer_out.json`, `obs_wallet_out.json`, `signet_observer.json`); only aggregate
numbers appear in the report.

## License
MIT — see [LICENSE](LICENSE).
