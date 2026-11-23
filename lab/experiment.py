#!/usr/bin/env python3
"""Deanon experiment runner (layer 2 validation): one broadcast, two vantages.

Topology:  spy --> ORIGIN <-> relay1 <-> relay2 <-- passive
The origin broadcasts a marked tx. The spy (direct peer of the origin) and the
passive observer (peer of the far relay) each record when and from whom they
first see it. Validates that the spy sees the ORIGIN announce it, while the
passive observer only sees a RELAY — the vantage difference, before rebroadcast.
"""
from __future__ import annotations
import time
from harness import Node, teardown, _p2p_up
from observer import ObserverSet


def build_network():
    teardown()
    origin = Node("origin", 0)
    relay1 = Node("relay1", 1)
    relay2 = Node("relay2", 2)
    origin.start()
    relay1.start(connect_to=[origin])
    relay2.start(connect_to=[relay1])
    for n in (origin, relay1, relay2):
        assert _p2p_up(n.p2p), f"{n.name} down"
    origin.rpc_call("createwallet", "w")
    addr = origin.rpc_call("getnewaddress", wallet="w")
    origin.rpc_call("generatetoaddress", 101, addr, wallet="w")
    for _ in range(40):
        if all(n.rpc_call("getblockchaininfo")["blocks"] == 101 for n in (relay1, relay2)):
            break
        time.sleep(0.25)
    return origin, relay1, relay2


def trial(window=30.0):
    origin, relay1, relay2 = build_network()
    obs = ObserverSet().start([
        ("spy",     "origin", "127.0.0.1", origin.p2p),
        ("passive", "relay2", "127.0.0.1", relay2.p2p),
    ], duration=window)
    time.sleep(3)  # let observers finish handshakes before we broadcast

    dest = origin.rpc_call("getnewaddress", wallet="w")
    txid = origin.rpc_call("sendtoaddress", dest, 1.0, wallet="w")
    print(f"broadcast marked tx {txid[:16]} from ORIGIN at t=+3s")

    time.sleep(window - 3 + 2)
    obs.join()

    print("\n--- announcements seen (time-ordered) ---")
    for fn, role, dt in obs.announcements(txid):
        print(f"  t=+{dt:5.1f}s   {role:8} observer saw it from {fn}")
    first = obs.first_by_role(txid)
    print("\n--- first announcement per vantage ---")
    for role in ("spy", "passive"):
        if role in first:
            fn, dt = first[role]
            print(f"  {role:8}: from {fn:8} at t=+{dt:.1f}s"
                  f"{'   <- directly implicates ORIGIN' if fn == 'origin' else '   (a relay, not the origin)'}")
        else:
            print(f"  {role:8}: (not seen in window)")

    for n in (origin, relay1, relay2):
        n.stop()
    teardown()
    return first


if __name__ == "__main__":
    trial()
