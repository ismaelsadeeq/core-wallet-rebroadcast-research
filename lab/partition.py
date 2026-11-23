#!/usr/bin/env python3
"""Compare, on one regtest graph with a LinkingLion observer inbound to every node:
  - a PASSIVE run (broadcast one tx, watch the announcement order), then
  - ANOTHER passive run (consistency), then
  - an ACTIVE run: broadcast a tx AND flood a conflicting double-spend from a
    well-connected attacker AT THE SAME TIME.

Passive localisation = who the observer hears first (source? a neighbour?).
Active localisation   = the first-seen-wins partition: which nodes commit to the
original vs the conflict. The still-original region should freeze to the source's
neighbourhood — a sticky bound the noisy passive order cannot give.

All regtest, our own coins. Env: TRIALS=5 SPACING=10
"""
import os, time
from collections import Counter
from harness import Node, teardown, _p2p_up
from observer import ObserverSet

IP = "127.0.0.1"
TRIALS = int(os.environ.get("TRIALS", "5"))
SPACING = float(os.environ.get("SPACING", "10"))

#       S
#      / \
#     A   B
#      \ / \
#       C   D
#        \ / \
#         E   F
#          \ /
#           G
HOP = {"S": 0, "A": 1, "B": 1, "C": 2, "D": 2, "E": 3, "F": 3, "G": 4}
CHILD_EDGES = {"S": [], "A": ["S"], "B": ["S"], "C": ["A", "B"], "D": ["B"],
               "E": ["C", "D"], "F": ["D"], "G": ["E", "F"]}
ORDER = ["S", "A", "B", "C", "D", "E", "F", "G"]


def main():
    teardown()
    nodes = {n: Node(n, i) for i, n in enumerate(ORDER)}
    for n in ORDER:
        nodes[n].start(connect_to=[nodes[p] for p in CHILD_EDGES[n]])
    AN = Node("AN", len(ORDER))                     # attacker: 1 hop from every node
    AN.start(connect_to=[nodes[n] for n in ORDER])
    alln = [nodes[n] for n in ORDER] + [AN]
    for n in alln:
        assert _p2p_up(n.p2p), f"{n.name} p2p down"

    S = nodes["S"]
    S.rpc_call("createwallet", "w")
    addr = S.rpc_call("getnewaddress", wallet="w")
    S.rpc_call("generatetoaddress", 150, addr, wallet="w")
    for _ in range(300):
        if all(x.rpc_call("getblockcount") == 150 for x in alln):
            break
        time.sleep(0.5)
    else:
        raise SystemExit("chain did not sync")

    ufree = [c for c in S.rpc_call("listunspent", 1, 9999999, [], True, wallet="w")
             if c["spendable"] and c["amount"] > 1]

    def build(u, dest):
        val = round(float(u["amount"]) - 0.001, 8)
        raw = S.rpc_call("createrawtransaction",
                         [{"txid": u["txid"], "vout": u["vout"]}], {dest: val})
        sg = S.rpc_call("signrawtransactionwithwallet", raw, wallet="w")
        assert sg["complete"]
        return sg["hex"], S.rpc_call("decoderawtransaction", sg["hex"])["txid"]

    window = TRIALS * 3 * SPACING + 60
    ll = ObserverSet().start([("ll", n, IP, nodes[n].p2p) for n in ORDER], window)
    time.sleep(3)

    passive_txids, active_pairs = [], []
    for t in range(TRIALS):
        # --- passive run 1 ---
        hx, tx = build(ufree.pop(), S.rpc_call("getnewaddress", wallet="w"))
        S.rpc_call("sendrawtransaction", hx); passive_txids.append(tx)
        time.sleep(SPACING)
        # --- passive run 2 ---
        hx, tx = build(ufree.pop(), S.rpc_call("getnewaddress", wallet="w"))
        S.rpc_call("sendrawtransaction", hx); passive_txids.append(tx)
        time.sleep(SPACING)
        # --- active run: original from S, conflict flooded from AN, same time ---
        u = ufree.pop()
        hexA, txidA = build(u, S.rpc_call("getnewaddress", wallet="w"))
        hexAp, txidAp = build(u, S.rpc_call("getnewaddress", wallet="w"))  # same input
        assert txidA != txidAp
        S.rpc_call("sendrawtransaction", hexA)
        try:
            AN.rpc_call("sendrawtransaction", hexAp)
            active_pairs.append((txidA, txidAp))
        except RuntimeError as e:
            print(f"  trial {t+1}: attacker already had original ({e}); skipping active")
        time.sleep(SPACING + 4)
        print(f"trial {t+1} done")

    time.sleep(8)
    ll.join()

    def seq(txid):
        seen, s = set(), []
        for fn, role, dt in ll.announcements(txid):
            if fn not in seen:
                seen.add(fn); s.append(fn)
        return s

    print("\n================  PASSIVE (announcement order)  ================")
    s_first = 0; first_ns = Counter(); usable = 0
    for tx in passive_txids:
        s = seq(tx)
        if len(s) < 3:
            continue
        usable += 1
        if s[0] == "S":
            s_first += 1
        ns = [n for n in s if n != "S"]
        if ns:
            first_ns[HOP[ns[0]]] += 1
    print(f"usable passive txs: {usable}")
    print(f"source announced first: {s_first}/{usable}")
    print("first non-source announcer by hop: " +
          ", ".join(f"hop{h}:{first_ns[h]}" for h in sorted(first_ns)))

    print("\n================  ACTIVE (double-spend partition)  ================")
    sizes, maxhops = [], []
    for txidA, txidAp in active_pairs:
        Aset = set(seq(txidA)); Apset = set(seq(txidAp))
        held = {n: ("A" if n in Aset else "A'" if n in Apset else "-") for n in ORDER}
        aregion = [n for n in ORDER if held[n] == "A"]
        sizes.append(len(aregion))
        maxhops.append(max((HOP[n] for n in aregion), default=-1))
        print(f"  {held}   A-region={aregion} maxhop={maxhops[-1]}")
    if sizes:
        print(f"\nA-region (nodes still holding the ORIGINAL after the flood):")
        print(f"  sizes {sizes}  (of {len(ORDER)} nodes)")
        print(f"  max hop from source {maxhops}  mean {sum(maxhops)/len(maxhops):.2f}")
        print(f"  => the conflict freezes the original to source + ~{round(sum(maxhops)/len(maxhops))} hop(s)")

    for n in alln:
        n.stop()
    teardown()


if __name__ == "__main__":
    main()
