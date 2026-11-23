### Rebroadcast source-attribution lab

A regtest lab that links an on-chain address to the node that controls it. The attacker sends
a small low-fee payment into a target's wallet (an address the target controls). It is too
small to confirm, so the target's node keeps it and re-announces it on its own 12-36 hour
timer. A spy connected to each candidate node sees which one re-announces the payment, and
that node controls the address. Wallet fingerprinting then adds which wallet software is
running on which node.

Because this is regtest we control every transaction, so we always know which node really
sent each one. That known answer is what the accuracy below is measured against.

Read RESULTS.md for the method and numbers. On regtest the spy linked the address to the
correct node in 30 of 30 trials; a single-vantage passive observer got 0. With
-walletbroadcast=0 the target's node does not re-announce and the spy learns nothing. There
is no trigger: the planted payment simply never confirms.

### Docker

Docker is for reproducibility and a bit of isolation: it pins a known wallet-enabled Bitcoin
Core 32.1 so the lab runs the same way on any machine, and it keeps the throwaway regtest
nodes contained instead of on your real system. It is not required. Point the harness at any
bitcoind that has a wallet and you can skip it. To use the pinned image, build it once:

```sh
docker build --build-arg VER=32.1 -t deanon-lab .
```

### Files

| file | role |
|---|---|
| `Dockerfile` | Debian + Core 32.1 (wallet): the lab image. |
| `harness.py` | Regtest node/RPC control (JSON-RPC over cookie), topology, funding. |
| `observer.py` | Regtest/signet P2P observers (spy + passive), built on `peer_probe`. |
| `experiment.py` | Layer-2 demo: one broadcast, spy-vs-passive vantage difference. |
| `rebroadcast_experiment.py` | Main experiment: planted-tx address-to-node attribution, `-walletbroadcast` ON/OFF defense, trials. |
| `network_sim.py` | 300-node regtest network: attacker advertises + listens, captures the non-listening (NAT'd) majority, plus live payment traffic to show diffusion timing. RAM-guarded. |
| `fingerprint_experiment.py` | Wallet fingerprint vs ground truth (+ discrimination control). |
| `signet_experiment.py` | Real-network observe→fingerprint check on public signet. |
| `RESULTS.md` | Method, numbers, debugging notes, limitations. |

Runtime artifacts `core/` (downloaded binaries) and `signet-data/` (synced chain, ~28 GB)
are gitignored.

### Run the main experiment

```sh
# from the repo root (bitcoin-deanon/)
docker run --rm -v "$PWD":/work -w /work/lab -e PYTHONPATH=/work/src deanon-lab \
    python3 rebroadcast_experiment.py        # spy vs passive, attack + defense

docker run --rm -v "$PWD":/work -v <wallet-fingerprinting>:/wf -w /work/lab \
    -e PYTHONPATH=/work/src:/wf:/wf/tqdm_shim deanon-lab \
    python3 fingerprint_experiment.py        # wallet fingerprint vs ground truth

docker run --rm -v "$PWD":/work -w /work/lab -e PYTHONPATH=/work/src deanon-lab \
    python3 network_sim.py 300 0.35 75       # 300-node capture + diffusion
```

Signet needs a synced node (a long-running container sharing its network namespace); see
the header of `signet_experiment.py`.
