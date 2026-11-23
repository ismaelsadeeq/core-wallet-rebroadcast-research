#!/usr/bin/env python3
"""Planted-tx source attribution: linking an address to a node (layer 3).

Star topology: a hub H (the sender/attacker) and K target nodes, each connected
to H. The attacker plants a small, low-fee payment into each target's wallet (a tx
that will not confirm); the target's wallet then re-announces that RECEIVED tx on
its own 12-36h resend timer, because Core's rebroadcast is not gated on the tx
being the wallet's own. Ground truth is the node controlling each receiving address.

Attack (spy): open a FRESH connection to each target after the planted tx is public.
A relay never re-announces an old mempool tx to a newly connected peer, so the only
node that re-announces the planted tx is the one whose wallet holds it: the target.

Baseline (passive): an observer on the hub only ever sees the hub (the sender)
announce, so it cannot identify the address-controlling target.

Defense: with -walletbroadcast=0 the target does not rebroadcast and the spy learns
nothing. (We fast-forward the resend timer with setmocktime; this is a time
mechanism, not a way to force a rebroadcast on demand.)

Run inside the lab container:
  docker run --rm -v $PWD:/work -w /work/lab -e PYTHONPATH=/work/src deanon-lab \
      python3 rebroadcast_experiment.py
"""
from __future__ import annotations
import time
from harness import Node, teardown, _p2p_up
from observer import ObserverSet

IP = "127.0.0.1"
RESEND_LIMIT = 36 * 3600   # upper bound of Core's wallet resend timer


def _sync_heights(nodes, h, tries=80):
    for _ in range(tries):
        if all(n.rpc_call("getblockchaininfo")["blocks"] == h for n in nodes):
            return True
        time.sleep(0.25)
    return False


def _await_mempool(node, txids, tries=80):
    want = set(txids)
    for _ in range(tries):
        if want <= set(node.rpc_call("getrawmempool")):
            return True
        time.sleep(0.25)
    return False


def run_trial(K=3, walletbroadcast=True, window=40.0):
    teardown()
    extra = [] if walletbroadcast else ["-walletbroadcast=0"]
    hub = Node("hub", 0)
    cands = [Node(f"cand{i}", i + 1, extra_args=extra) for i in range(K)]
    hub.start()
    for c in cands:
        c.start(connect_to=[hub])
    for n in [hub, *cands]:
        assert _p2p_up(n.p2p), f"{n.name} down"

    # fund the hub (the sender/attacker); candidates only RECEIVE, so need no funds
    hub.rpc_call("createwallet", "w")
    haddr = hub.rpc_call("getnewaddress", wallet="w")
    hub.rpc_call("generatetoaddress", 150, haddr, wallet="w")
    for c in cands:
        c.rpc_call("createwallet", "w")
    assert _sync_heights([hub, *cands], 150), "chain did not sync"

    # passive baseline: an observer on the hub only ever sees the hub (the sender)
    # announce, never the address-controlling candidate.
    passive = ObserverSet().start([("passive", "hub", IP, hub.p2p)], window)
    time.sleep(2)

    # ATTACK (realistic): the sender plants a small payment into each candidate's
    # wallet -- a low-fee tx that will not confirm. Ground truth is the node that
    # CONTROLS the receiving address. No rebroadcast is "triggered": the candidate's
    # own wallet will resend the received tx on its 12-36h timer (Core's rebroadcast
    # is not gated on the tx being the wallet's own), and we fast-forward that timer.
    truth, cand_tx = {}, {}
    for c in cands:
        addr = c.rpc_call("getnewaddress", wallet="w")
        txid = hub.rpc_call("sendtoaddress", addr, 0.001, wallet="w")
        truth[txid] = c.name; cand_tx[c.name] = txid
    assert _await_mempool(hub, truth), "planted txs did not propagate"
    for c in cands:
        assert _await_mempool(c, [cand_tx[c.name]]), f"{c.name} never saw its planted tx"

    # a planted tx is only rebroadcast once >=5 min older than the best block: mine
    # an EMPTY block 10 min ahead in mocktime (keeps the txs unconfirmed).
    t0 = int(time.time())
    for n in [hub, *cands]:
        n.rpc_call("setmocktime", t0 + 600)
    hub.rpc_call("generateblock", haddr, [], wallet="w")
    assert _sync_heights([hub, *cands], 151), "empty block did not sync"

    # Jump past the resend timer FIRST (a +36h jump evicts already-connected peers),
    # THEN connect the fresh spies, THEN let each candidate's wallet resend its
    # RECEIVED tx on the now-elapsed timer.
    base = t0 + 600 + RESEND_LIMIT
    for n in [hub, *cands]:
        n.rpc_call("setmocktime", base)
    spy = ObserverSet().start(
        [(f"spy:{c.name}", c.name, IP, c.p2p) for c in cands], window)
    time.sleep(3)
    for c in cands:
        c.rpc_call("mockscheduler", 60)
    # inbound peers share a Poisson inv timer rescheduled ~5s into the mock-future,
    # so step the clock generously (12x5s) to guarantee every spy's inv flushes.
    for k in range(1, 13):
        for n in [hub, *cands]:
            n.rpc_call("setmocktime", base + k * 5)
        time.sleep(1)
    spy.join(); passive.join()

    # attribution
    def accuracy(obs):
        hits = 0
        preds = {}
        for tx, origin in truth.items():
            anns = obs.announcements(tx)
            pred = anns[0][0] if anns else None     # first node to announce it to us
            preds[tx] = pred
            hits += (pred == origin)
        return hits / len(truth), preds

    spy_acc, spy_pred = accuracy(spy)
    pas_acc, pas_pred = accuracy(passive)
    for n in [hub, *cands]:
        n.stop()
    teardown()
    return {"walletbroadcast": walletbroadcast, "K": K,
            "spy_acc": spy_acc, "passive_acc": pas_acc,
            "spy_pred": spy_pred, "passive_pred": pas_pred, "truth": truth}


def main(K=5, trials=6):
    print(f"Planted-tx source attribution  (K={K} targets/trial, {trials} trials, "
          f"{K*trials} attributions/arm)")
    print("=" * 70)
    for wb in (True, False):
        spy_hits = pas_hits = total = 0
        for t in range(trials):
            r = run_trial(K=K, walletbroadcast=wb)
            n = len(r["truth"])
            spy_hits += round(r["spy_acc"] * n); pas_hits += round(r["passive_acc"] * n); total += n
        tag = "ON (attack)" if wb else "OFF (target wallet does not rebroadcast)"
        print(f"\n[walletbroadcast {tag}]")
        print(f"  spy attribution    : {spy_hits}/{total}  ({100*spy_hits/total:.1f}%)")
        print(f"  passive (baseline) : {pas_hits}/{total}  ({100*pas_hits/total:.1f}%)   random = {100/K:.0f}%")


if __name__ == "__main__":
    main()
