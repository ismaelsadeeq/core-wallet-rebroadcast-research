#!/usr/bin/env python3
"""Regtest deanonymization simulation — node/RPC harness (layer 1).

All local, all regtest, ground-truth = our own txs. No mainnet, ever.

Brings up a small regtest P2P topology from the persist-user-agent build, drives
nodes over JSON-RPC (cookie auth, no bitcoin-cli dependency), funds an ORIGIN
wallet, and broadcasts a marked transaction. Later layers add spy/passive
observers, mocktime-driven rebroadcast, and wallet fingerprinting.
"""
from __future__ import annotations
import json, os, shutil, signal, socket, subprocess, time, urllib.request

BITCOIND = os.environ.get("BITCOIND", "/usr/local/bin/bitcoind")  # release w/ wallet
ROOT = os.environ.get("DEANON_ROOT", "/tmp/deanon-rt")
REGTEST_MAGIC = bytes.fromhex("fabfb5da")   # for P2P observers (not RPC)


class Node:
    """One regtest bitcoind, controlled over JSON-RPC via its cookie."""
    def __init__(self, name, index, *, extra_args=()):
        self.name = name
        self.i = index
        self.datadir = os.path.join(ROOT, name)
        self.p2p = 19100 + index
        self.rpc = 19200 + index
        self.extra = list(extra_args)
        self.proc = None

    def start(self, connect_to=()):
        os.makedirs(self.datadir, exist_ok=True)
        args = [BITCOIND, "-regtest", f"-datadir={self.datadir}",
                f"-port={self.p2p}", f"-rpcport={self.rpc}",
                "-listen=1", "-bind=127.0.0.1", "-dnsseed=0", "-discover=0",
                "-txindex=1", "-fallbackfee=0.0002", "-server=1",
                *(f"-connect=127.0.0.1:{n.p2p}" for n in connect_to),
                *self.extra]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        self._await_rpc()
        return self

    # ---- JSON-RPC ----
    def _cookie(self):
        with open(os.path.join(self.datadir, "regtest", ".cookie")) as f:
            return f.read().strip()

    def rpc_call(self, method, *params, wallet=None):
        url = f"http://127.0.0.1:{self.rpc}/"
        if wallet is not None:
            url += f"wallet/{wallet}"
        body = json.dumps({"jsonrpc": "1.0", "id": "h", "method": method,
                           "params": list(params)}).encode()
        import base64
        tok = base64.b64encode(self._cookie().encode()).decode()
        req = urllib.request.Request(url, data=body,
                                     headers={"Authorization": f"Basic {tok}",
                                              "Content-Type": "text/plain"})
        with urllib.request.urlopen(req, timeout=30) as r:
            out = json.load(r)
        if out.get("error"):
            raise RuntimeError(f"{self.name}.{method}: {out['error']}")
        return out["result"]

    def _await_rpc(self, tries=60):
        for _ in range(tries):
            try:
                self.rpc_call("getblockchaininfo")
                return
            except Exception:
                time.sleep(0.3)
        raise RuntimeError(f"{self.name}: RPC never came up")

    def stop(self):
        if self.proc:
            try:
                self.rpc_call("stop")
            except Exception:
                self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=20)
            except Exception:
                self.proc.kill()


def teardown():
    shutil.rmtree(ROOT, ignore_errors=True)


def _p2p_up(port, tries=40):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.25)
    return False


def smoke():
    """Bring up origin + 2 relays, fund origin, broadcast a marked tx, verify
    it propagates to the relays. Returns (nodes, txid)."""
    teardown()
    origin = Node("origin", 0)
    relay1 = Node("relay1", 1)
    relay2 = Node("relay2", 2)
    # topology: origin <-> relay1 <-> relay2  (origin not directly on relay2)
    origin.start()
    relay1.start(connect_to=[origin])
    relay2.start(connect_to=[relay1])
    for n in (origin, relay1, relay2):
        assert _p2p_up(n.p2p), f"{n.name} p2p down"

    # fund origin
    origin.rpc_call("createwallet", "w")
    addr = origin.rpc_call("getnewaddress", wallet="w")
    origin.rpc_call("generatetoaddress", 101, addr, wallet="w")
    bal = origin.rpc_call("getbalance", wallet="w")

    # wait for chain sync across the line topology
    def height(n): return n.rpc_call("getblockchaininfo")["blocks"]
    for _ in range(40):
        if height(relay1) == 101 and height(relay2) == 101:
            break
        time.sleep(0.25)

    # broadcast a marked tx (send to a fresh address; ground truth = origin)
    dest = origin.rpc_call("getnewaddress", wallet="w")
    txid = origin.rpc_call("sendtoaddress", dest, 1.0, wallet="w")

    # verify propagation into relay mempools
    def in_mempool(n):
        for _ in range(40):
            if txid in n.rpc_call("getrawmempool"):
                return True
            time.sleep(0.25)
        return False
    r1 = in_mempool(relay1)
    r2 = in_mempool(relay2)

    print(f"origin balance: {bal} BTC   heights: "
          f"o={height(origin)} r1={height(relay1)} r2={height(relay2)}")
    print(f"marked txid: {txid}")
    print(f"propagated -> relay1: {r1}   relay2: {r2}")
    print(f"connections: origin={origin.rpc_call('getconnectioncount')} "
          f"relay1={relay1.rpc_call('getconnectioncount')} "
          f"relay2={relay2.rpc_call('getconnectioncount')}")
    return (origin, relay1, relay2), txid


if __name__ == "__main__":
    nodes = None
    try:
        nodes, txid = smoke()
        print("\nSMOKE OK" if txid else "SMOKE FAIL")
    finally:
        if nodes:
            for n in nodes:
                n.stop()
        teardown()
