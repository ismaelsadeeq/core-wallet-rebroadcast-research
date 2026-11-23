#!/usr/bin/env python3
"""Does planting the conflict at a SPECIFIC candidate peer (not flooding everywhere)
reveal the source's neighbourhood? Inject the original at source S and the conflict
at a plant-point P simultaneously; the network splits into an S-camp and a P-camp
(first-seen-wins, sticky). Measure whether the S-camp size/shape tracks P's hop
distance from S -- i.e. whether the split carries adjacency information.

Ground truth read from each node's mempool (in a real attack the observer reads the
same partition from announcements). All regtest, our own coins. Env: TRIALS=3
"""
import os, time
from collections import defaultdict
from harness import Node, teardown, _p2p_up

TRIALS = int(os.environ.get("TRIALS", "3"))
SETTLE = 16.0
HOP = {"S": 0, "A": 1, "B": 1, "C": 2, "D": 2, "E": 3, "F": 3, "G": 4}
CHILD_EDGES = {"S": [], "A": ["S"], "B": ["S"], "C": ["A", "B"], "D": ["B"],
               "E": ["C", "D"], "F": ["D"], "G": ["E", "F"]}
ORDER = ["S", "A", "B", "C", "D", "E", "F", "G"]
PLANTS = ["A", "C", "E", "G"]          # candidate plant-points at hop 1, 2, 3, 4


def main():
    teardown()
    nodes = {n: Node(n, i) for i, n in enumerate(ORDER)}
    for n in ORDER:
        nodes[n].start(connect_to=[nodes[p] for p in CHILD_EDGES[n]])
    for n in nodes.values():
        assert _p2p_up(n.p2p), f"{n.name} p2p down"
    S = nodes["S"]
    S.rpc_call("createwallet", "w")
    addr = S.rpc_call("getnewaddress", wallet="w")
    S.rpc_call("generatetoaddress", 200, addr, wallet="w")
    for _ in range(300):
        if all(x.rpc_call("getblockcount") == 200 for x in nodes.values()):
            break
        time.sleep(0.5)
    else:
        raise SystemExit("no sync")

    ufree = [c for c in S.rpc_call("listunspent", 1, 9999999, [], True, wallet="w")
             if c["spendable"] and c["amount"] > 1]

    def build(u, dest):
        val = round(float(u["amount"]) - 0.001, 8)
        raw = S.rpc_call("createrawtransaction",
                         [{"txid": u["txid"], "vout": u["vout"]}], {dest: val})
        sg = S.rpc_call("signrawtransactionwithwallet", raw, wallet="w")
        assert sg["complete"]
        return sg["hex"], S.rpc_call("decoderawtransaction", sg["hex"])["txid"]

    def clear():
        a = S.rpc_call("getnewaddress", wallet="w")
        S.rpc_call("generatetoaddress", 1, a, wallet="w")
        h = S.rpc_call("getblockcount")
        for _ in range(120):
            if all(x.rpc_call("getblockcount") == h for x in nodes.values()):
                return
            time.sleep(0.5)

    results = defaultdict(list)      # plant_hop -> list of (S-camp set, P-camp size)
    for P in PLANTS:
        for t in range(TRIALS):
            u = ufree.pop()
            hexA, txidA = build(u, S.rpc_call("getnewaddress", wallet="w"))
            hexAp, txidAp = build(u, S.rpc_call("getnewaddress", wallet="w"))
            assert txidA != txidAp
            S.rpc_call("sendrawtransaction", hexA)
            try:
                nodes[P].rpc_call("sendrawtransaction", hexAp)
            except RuntimeError as e:
                print(f"  plant {P} trial {t+1}: P already had original ({e}); skip")
                clear(); continue
            time.sleep(SETTLE)
            camp = {}
            for n in ORDER:
                mp = set(nodes[n].rpc_call("getrawmempool"))
                camp[n] = "S" if txidA in mp else "P" if txidAp in mp else "-"
            scamp = [n for n in ORDER if camp[n] == "S"]
            pcamp = [n for n in ORDER if camp[n] == "P"]
            results[HOP[P]].append((scamp, len(pcamp)))
            print(f"  plant {P}(hop{HOP[P]}) t{t+1}: S-camp={scamp}  P-camp={pcamp}")
            clear()

    print("\n==== does the S-camp size track the plant distance? ====")
    for hop in sorted(results):
        rows = results[hop]
        sizes = [len(sc) for sc, _ in rows]
        # which non-source nodes stay with S most often (candidate S-neighbours)
        stay = defaultdict(int)
        for sc, _ in rows:
            for n in sc:
                if n != "S":
                    stay[n] += 1
        stayed = ", ".join(f"{n}:{c}/{len(rows)}" for n, c in
                           sorted(stay.items(), key=lambda kv: -kv[1]))
        print(f"  plant hop {hop}: mean S-camp {sum(sizes)/len(sizes):.1f} "
              f"(sizes {sizes});  nodes staying with S: {stayed}")

    for n in nodes.values():
        n.stop()
    teardown()


if __name__ == "__main__":
    main()
