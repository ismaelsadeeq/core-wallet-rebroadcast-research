#!/usr/bin/env python3
"""Signet real-network validation of the observe -> fingerprint pipeline.

The rebroadcast *attribution* is measured in regtest (it needs a controllable
clock; a +36h mocktime jump would desync a live-networked node from real peers).
This script validates the rest of the pipeline on the REAL signet network: it
observes genuine transaction announcements from our synced signet node and
fingerprints the originating wallet of each — proving the instrumentation works
outside the lab, against mainnet-like Core over a real P2P network.

Run in a sidecar sharing the signet node's network namespace:
  docker run --rm --network container:deanon-signet \
     -v <peer-probe>:/work -v <wf>:/wf -w /work/lab \
     -e PYTHONPATH=/work/src:/wf:/wf/tqdm_shim deanon-lab python3 signet_experiment.py <seconds>
"""
import os, sys, time, json, urllib.request, base64
from collections import Counter
from observer import ObserverSet

SIGNET_MAGIC = bytes.fromhex("0a03cf40")   # default (global) signet message start
RPC = ("127.0.0.1", 38332, "u", "p")       # signet node RPC (started with -rpcuser/-rpcpassword)
P2P = ("127.0.0.1", 38333)
WF = "/wf"


def rpc(method, *params):
    url = f"http://{RPC[0]}:{RPC[1]}/"
    body = json.dumps({"method": method, "params": list(params)}).encode()
    tok = base64.b64encode(f"{RPC[2]}:{RPC[3]}".encode()).decode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Authorization": f"Basic {tok}",
                                          "Content-Type": "text/plain"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["result"]


def main(seconds=90):
    info = rpc("getblockchaininfo")
    print(f"signet node: height={info['blocks']} ibd={info['initialblockdownload']} "
          f"peers={rpc('getconnectioncount')}")

    # observe real tx announcements from our own node (it relays live signet traffic)
    obs = ObserverSet()
    obs.start([("passive", "signet-node", P2P[0], P2P[1])], duration=seconds)
    print(f"observing real signet tx announcements for {seconds}s ...")
    time.sleep(seconds + 2)
    obs.join()

    txids = {tx for (tx, _, _) in obs.sink}
    print(f"observed {len(obs.sink)} inv rows, {len(txids)} distinct txids")

    # fingerprint the wallet of a sample (those still fetchable from our mempool/chain)
    os.chdir(WF)
    with open("rpc_config.ini", "w") as f:
        f.write(f"[RPC_INFO]\nURL = http://{RPC[0]}:{RPC[1]}/\n"
                f"RPCUSER = {RPC[2]}\nRPCPASSWORD = {RPC[3]}\n")
    import fingerprinting

    def conf_height(txid):
        try:
            r = rpc("getrawtransaction", txid, True)
            return rpc("getblockheader", r["blockhash"])["height"] if "blockhash" in r else -1
        except Exception:
            return -1
    fingerprinting.get_confirmation_height = conf_height

    # fetch prevouts from the UTXO set as-of-chain (no txindex needed; our node
    # has none). include_mempool=False so an output spent by *this* mempool tx is
    # still readable.
    def get_prev_txout(tx_in):
        o = rpc("gettxout", tx_in["txid"], tx_in["vout"], False)
        if o is None:
            raise KeyError("prevout is itself unconfirmed")
        return o
    fingerprinting.module.get_prev_txout = get_prev_txout

    # Signet tx rate is low, so live announcement capture is sparse; fingerprint a
    # sample of the live mempool (real signet txs) for a robust pipeline check.
    sample = (list(txids) or rpc("getrawmempool"))[:120]
    dist = Counter(); fp = 0
    for txid in sample:
        try:
            wallets, _ = fingerprinting.detect_wallet(fingerprinting.module.get_tx(txid))
            label = "|".join(sorted(w.value for w in wallets)) if wallets else "(none/unclear)"
            dist[label] += 1; fp += 1
        except Exception as e:
            dist["skip:" + type(e).__name__] += 1
    print(f"\nfingerprinted {fp} real signet txs (sample of {len(sample)}); wallet distribution:")
    for label, c in dist.most_common():
        print(f"  {c:3}  {label}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 90)
