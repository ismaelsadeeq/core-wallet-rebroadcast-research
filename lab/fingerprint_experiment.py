#!/usr/bin/env python3
"""Wallet-fingerprint ground truth (layer 4).

Each tx in the deanon sim is originated by a known wallet. This joins the
construction-heuristic wallet fingerprint (Ishaana Misra's detect_wallet) onto
the origin attribution: for a captured tx we learn BOTH who sent it (rebroadcast)
and what wallet built it (fingerprint). Here we validate the fingerprint against
ground truth on regtest-originated transactions.

Reuses the real detect_wallet logic from the wallet-fingerprinting repo (mounted
at /wf). Points its RPC at our origin node and overrides get_confirmation_height
to use the local node (the upstream version queries mempool.space, which does not
know regtest txs).

Run inside the lab container (wallet-fingerprinting mounted at /wf):
  docker run --rm -v $PWD:/work -v <wf>:/wf -w /work/lab \
      -e PYTHONPATH=/work/src:/wf:/wf/tqdm_shim deanon-lab python3 fingerprint_experiment.py
"""
import os, sys, time
from harness import Node, teardown

WF = "/wf"


def fingerprint_core_txs(n=3):
    teardown()
    origin = Node("origin", 0)
    origin.start()
    origin.rpc_call("createwallet", "w")
    addr = origin.rpc_call("getnewaddress", wallet="w")
    origin.rpc_call("generatetoaddress", 101, addr, wallet="w")

    # originate a few Core txs with varied shapes, then confirm them
    txids = []
    for i in range(n):
        dest = origin.rpc_call("getnewaddress", wallet="w")
        txids.append(origin.rpc_call("sendtoaddress", dest, 1.0 + i, wallet="w"))
    origin.rpc_call("generatetoaddress", 1, addr, wallet="w")   # confirm (for conf-height)

    # point the fingerprinting backend at our node, THEN import it
    os.chdir(WF)
    user, pw = origin._cookie().split(":", 1)          # cookie = "__cookie__:hex"
    with open("rpc_config.ini", "w") as f:
        f.write(f"[RPC_INFO]\nURL = http://127.0.0.1:{origin.rpc}/\n"
                f"RPCUSER = {user}\nRPCPASSWORD = {pw}\n")
    import fingerprinting

    def local_conf_height(txid):
        r = origin.rpc_call("getrawtransaction", txid, True)
        if "blockhash" not in r:
            return -1
        return origin.rpc_call("getblockheader", r["blockhash"])["height"]
    fingerprinting.get_confirmation_height = local_conf_height   # override mempool.space

    results = []
    for txid in txids:
        esplora = fingerprinting.module.get_tx(txid)
        wallets, reasoning = fingerprinting.detect_wallet(esplora)
        label = "|".join(sorted(w.value for w in wallets)) if wallets else "(none)"
        results.append(("core-wallet", txid, label, reasoning))

    # discrimination control: a hand-built tx with locktime=0 (no anti-fee-sniping),
    # i.e. a different construction than Core's wallet. The detector should move it
    # AWAY from the Core/Electrum class -- showing it responds to construction, not noise.
    u = next(x for x in origin.rpc_call("listunspent", wallet="w") if x["amount"] > 2)
    dest = origin.rpc_call("getnewaddress", wallet="w")
    raw = origin.rpc_call("createrawtransaction",
                          [{"txid": u["txid"], "vout": u["vout"]}],
                          {dest: round(u["amount"] - 0.001, 8)})      # locktime defaults to 0
    signed = origin.rpc_call("signrawtransactionwithwallet", raw, wallet="w")["hex"]
    vtxid = origin.rpc_call("sendrawtransaction", signed)
    origin.rpc_call("generatetoaddress", 1, addr, wallet="w")
    vw, vr = fingerprinting.detect_wallet(fingerprinting.module.get_tx(vtxid))
    vlabel = "|".join(sorted(w.value for w in vw)) if vw else "(none)"
    results.append(("locktime0-variant", vtxid, vlabel, vr))

    origin.stop(); teardown()
    return results


def main():
    print("Wallet fingerprint vs ground truth")
    print("=" * 66)
    res = fingerprint_core_txs(3)
    core = [r for r in res if r[0] == "core-wallet"]
    correct = sum("Bitcoin Core" in r[2] for r in core)
    print("Core-wallet txs (ground truth = Bitcoin Core):")
    for _, txid, label, _ in core:
        print(f"  {txid[:16]}  -> {label:28} {'OK' if 'Bitcoin Core' in label else 'MISS'}")
    print(f"  => {correct}/{len(core)} identified as Bitcoin Core")
    print("\nDiscrimination control (hand-built locktime=0 tx, NOT Core's construction):")
    for _, txid, label, reasoning in [r for r in res if r[0] == "locktime0-variant"]:
        moved = "Bitcoin Core" not in label
        print(f"  {txid[:16]}  -> {label:28} {'DISCRIMINATED (not Core)' if moved else 'still Core'}")
        print(f"  reasoning: {reasoning}")


if __name__ == "__main__":
    main()
