#!/usr/bin/env python3
"""Empirical: with a LinkingLion connected to EVERY node, does the ORDER in which
nodes announce a tx to it track hop-distance from the source (=> topology leaks),
or does the exponential inbound-inv timer scramble it?

Complex regtest graph, known hop-distance from source S. One observer
(LinkingLion) opens a relay-on connection to every node and records, per tx, the
time-ordered list of which node announced it.

Two relay directions, selectable:
  REVERSE=0 (default): child -connect parent  -> parent relays DOWN via its 5s
            INBOUND timer (the same timer LinkingLion is on): coupled.
  REVERSE=1:          parent -connect child   -> parent relays DOWN via its 2s
            OUTBOUND timer, decoupled from LinkingLion's 5s inbound view
            (closer to how a real node relays to outbound peers).

Env: REVERSE=0|1  TRIALS=3  ROUNDS=16

  docker run --rm --tmpfs /tmp/deanon-rt:rw,size=3g -v "$PWD":/work -w /work/lab \
      -e PYTHONPATH=/work/src -e REVERSE=0 -e TRIALS=3 deanon-lab python3 topo_timing.py
"""
import os, time
from collections import Counter, defaultdict
from harness import Node, teardown, _p2p_up
from observer import ObserverSet

IP = "127.0.0.1"
ROUNDS = int(os.environ.get("ROUNDS", "16"))
TRIALS = int(os.environ.get("TRIALS", "3"))
REVERSE = os.environ.get("REVERSE", "0") == "1"
SPACING = 8.0

#   S
#  / \
# A   B
#  \ / \
#   C   D
#    \ / \
#     E   F
#      \ /
#       G
HOP = {"S": 0, "A": 1, "B": 1, "C": 2, "D": 2, "E": 3, "F": 3, "G": 4}
CHILD_EDGES = {"S": [], "A": ["S"], "B": ["S"], "C": ["A", "B"], "D": ["B"],
               "E": ["C", "D"], "F": ["D"], "G": ["E", "F"]}
ORDER = ["S", "A", "B", "C", "D", "E", "F", "G"]


def build_edges():
    if not REVERSE:
        return CHILD_EDGES, ORDER                 # child connects to parent
    rev = {n: [] for n in ORDER}                  # parent connects to child
    for child, parents in CHILD_EDGES.items():
        for p in parents:
            rev[p].append(child)
    return rev, list(reversed(ORDER))             # start children first


def run_trial():
    teardown()
    edges, start_order = build_edges()
    nodes = {name: Node(name, i) for i, name in enumerate(ORDER)}
    for name in start_order:
        nodes[name].start(connect_to=[nodes[p] for p in edges[name]])
    for n in nodes.values():
        assert _p2p_up(n.p2p), f"{n.name} p2p down"

    S = nodes["S"]
    S.rpc_call("createwallet", "w")
    addr = S.rpc_call("getnewaddress", wallet="w")
    S.rpc_call("generatetoaddress", 101, addr, wallet="w")
    for _ in range(160):
        if all(n.rpc_call("getblockcount") == 101 for n in nodes.values()):
            break
        time.sleep(0.5)
    else:
        raise SystemExit("chain did not sync across topology")

    window = ROUNDS * SPACING + 45
    ll = ObserverSet().start([("ll", n, IP, nodes[n].p2p) for n in ORDER], window)
    time.sleep(3)
    txids = []
    for _ in range(ROUNDS):
        a = S.rpc_call("getnewaddress", wallet="w")
        txids.append(S.rpc_call("sendtoaddress", a, 0.01, wallet="w"))
        time.sleep(SPACING)
    time.sleep(35)
    ll.join()

    seqs = []
    for txid in txids:
        seen, seq = set(), []
        for node, role, dt in ll.announcements(txid):
            if node not in seen:
                seen.add(node); seq.append(node)
        if len(seq) >= 3:
            seqs.append(seq)
    for n in nodes.values():
        n.stop()
    return seqs


def main():
    print(f"=== relay direction: {'OUTBOUND(2s), decoupled' if REVERSE else 'INBOUND(5s), coupled'}"
          f"   trials={TRIALS} rounds/trial={ROUNDS} ===")
    all_seqs = []
    for t in range(TRIALS):
        seqs = run_trial()
        all_seqs += seqs
        print(f"trial {t+1}: {len(seqs)} usable txs")

    s_first = sum(1 for s in all_seqs if s[0] == "S")
    first_ns_hop = Counter()
    far_beats_near = 0
    rank0 = Counter(); rank1 = Counter()
    rank_sum = defaultdict(float); rank_n = defaultdict(int)
    for s in all_seqs:
        rank0[HOP[s[0]]] += 1
        if len(s) > 1:
            rank1[HOP[s[1]]] += 1
        nons = [n for n in s if n != "S"]
        if nons:
            first_ns_hop[HOP[nons[0]]] += 1
        pos = {n: i for i, n in enumerate(s)}
        near = [pos[x] for x in ("A", "B") if x in pos]
        far = [pos[x] for x in ("E", "F", "G") if x in pos]
        if near and far and min(far) < max(near):
            far_beats_near += 1
        for rank, n in enumerate(s):
            rank_sum[HOP[n]] += rank; rank_n[HOP[n]] += 1

    N = len(all_seqs)
    print(f"\nTOTAL usable txs: {N}")
    print(f"S (source) first:                 {s_first}/{N} ({100*s_first//max(N,1)}%)")
    print("first NON-source announcer by hop: " +
          ", ".join(f"hop{h}:{first_ns_hop[h]}" for h in sorted(first_ns_hop)))
    print(f"a >=3-hop node beat a 1-hop node: {far_beats_near}/{N} ({100*far_beats_near//max(N,1)}%)")
    def _dist(c): return ", ".join(f"hop{h}={c[h]}({100*c[h]//max(sum(c.values()),1)}%)" for h in sorted(c))
    print(f"1st announcer by hop: {_dist(rank0)}")
    print(f"2nd announcer by hop: {_dist(rank1)}")
    print("avg announcement rank by hop (0=first; monotonic => order leaks hops):")
    for h in sorted(rank_sum):
        print(f"  hop {h}: {rank_sum[h]/rank_n[h]:.2f}  (n={rank_n[h]})")


if __name__ == "__main__":
    main()
