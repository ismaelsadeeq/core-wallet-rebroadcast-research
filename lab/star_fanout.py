#!/usr/bin/env python3
"""Reconcile regtest Core with Hyperion: does the source-first rate fall toward
Hyperion's ~40% as the source's fanout grows? Decoupled star (source relays to K
leaves over its 2s OUTBOUND timer), observer inbound to all, source broadcasts;
measure how often the observer hears the SOURCE before any leaf, for K in {2,8,16}.

Env: ROUNDS=14
"""
import os, time
from harness import Node, teardown, _p2p_up
from observer import ObserverSet

IP = "127.0.0.1"
ROUNDS = int(os.environ.get("ROUNDS", "14"))
SPACING = 7.0
KS = [2, 8, 16]


def run_star(K):
    teardown()
    leaves = [Node(f"L{j}", j + 1) for j in range(K)]
    for lf in leaves:
        lf.start()                                   # listen only
    S = Node("S", 0)
    S.start(connect_to=leaves)                       # S -> leaf = decoupled 2s outbound relay
    alln = [S] + leaves
    for n in alln:
        assert _p2p_up(n.p2p), f"{n.name} down"

    S.rpc_call("createwallet", "w")
    addr = S.rpc_call("getnewaddress", wallet="w")
    S.rpc_call("generatetoaddress", 150, addr, wallet="w")
    for _ in range(300):
        if all(x.rpc_call("getblockcount") == 150 for x in alln):
            break
        time.sleep(0.5)
    else:
        raise SystemExit(f"K={K}: no sync")

    window = ROUNDS * SPACING + 45
    specs = [("ll", "S", IP, S.p2p)] + [("ll", lf.name, IP, lf.p2p) for lf in leaves]
    ll = ObserverSet().start(specs, window)
    time.sleep(3)
    txids = []
    for _ in range(ROUNDS):
        a = S.rpc_call("getnewaddress", wallet="w")
        txids.append(S.rpc_call("sendtoaddress", a, 0.01, wallet="w"))
        time.sleep(SPACING)
    time.sleep(30)
    ll.join()

    s_first = usable = 0
    for tx in txids:
        order = [fn for fn, role, dt in ll.announcements(tx)]
        seq = []
        for fn in order:
            if fn not in seq:
                seq.append(fn)
        if len(seq) < 2:
            continue
        usable += 1
        if seq[0] == "S":
            s_first += 1
    for n in alln:
        n.stop()
    teardown()
    return s_first, usable


def main():
    print(f"decoupled star, ROUNDS={ROUNDS}/K; source-first vs fanout K:")
    for K in KS:
        sf, u = run_star(K)
        print(f"  K={K:2d} neighbours:  source heard first {sf}/{u} "
              f"({100*sf//max(u,1)}%)")
    print("Hyperion realistic mix (~16 neighbours): ~40% for reference")


if __name__ == "__main__":
    main()
