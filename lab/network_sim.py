#!/usr/bin/env python3
"""~300-node regtest network: the attacker advertises its address and listens,
and captures the non-listening (NAT'd) majority (layer 4, scale test).

Every crawler, and the small lab in rebroadcast_experiment.py, sees only LISTENING
nodes. The non-listening majority accepts no inbound, so nobody can connect to it.
The one way to observe such a node is to make it connect to YOU: run a listening
node, advertise its address widely, and the non-listening node dials out to you and
becomes your inbound peer.

This brings up N real `bitcoind -regtest` nodes (official Core, via the lab image):
  - attacker A : listening, high connection limit, the vantage.
  - listening  : accept inbound; A reaches them by dialing out (what a crawler does).
  - non-listening (`-listen=0`): accept NO inbound; the only way A sees one is if it
    dials A. Each learns A's advertised address and opens an outbound to it.

We then read A's getpeerinfo and count, by role, who connected. Each node carries a
unique `-uacomment=nK`, so an inbound peer's subver maps back to its node and role.

Honesty notes (lab artifacts, not properties of the real attack):
  - All nodes share 127.0.0.1, one netgroup, so Core's normal multi-outbound addrman
    selection (one-per-netgroup, anti-eclipse) cannot spread connections here. We
    therefore model "node learned A's advertised address and connects to it" with an
    `-addnode` to A. The connection DIRECTION (NAT'd node -> A, inbound at A) is the
    real phenomenon; only how it learned the address is shortcut.
  - Address learning is modeled; in the field A's address propagates by addr gossip.

RAM: each node is capped small and startup is batched; MemAvailable is checked after
every batch and the run aborts before exhausting host memory.

Run inside the lab container:
  docker run --rm -v $PWD:/work -w /work/lab -e PYTHONPATH=/work/src deanon-lab \
      python3 network_sim.py [N] [listen_frac]
"""
from __future__ import annotations
import os, re, sys, time, signal, subprocess
from harness import Node, teardown, BITCOIND, ROOT

IP = "127.0.0.1"
BATCH = 30                 # nodes launched per batch before a RAM check
RAM_FLOOR_MB = 2500        # abort a batch if MemAvailable drops below this
LIGHT = ["-dbcache=4", "-maxmempool=5", "-par=1", "-txindex=0",
         "-dnsseed=0", "-discover=0", "-server=1", "-fallbackfee=0.0002"]
BIND = "-bind=127.0.0.1"   # only valid with -listen=1 (Core refuses -bind + -listen=0)


def mem_available_mb():
    for line in open("/proc/meminfo"):
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    return None


def bitcoind_rss_mb():
    """Summed RSS of all bitcoind processes, read straight from /proc (no ps)."""
    total = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            if open(f"/proc/{pid}/comm").read().strip() != "bitcoind":
                continue
            for line in open(f"/proc/{pid}/status"):
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1]); break
        except (OSError, ValueError):
            continue
    return total // 1024 if total else None


def launch(node, args):
    """Start a node's bitcoind WITHOUT waiting for RPC (batched elsewhere)."""
    os.makedirs(node.datadir, exist_ok=True)
    full = [BITCOIND, "-regtest", f"-datadir={node.datadir}",
            f"-port={node.p2p}", f"-rpcport={node.rpc}",
            f"-uacomment=n{node.i}", *args]
    node.proc = subprocess.Popen(full, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)


def await_rpc(node, tries=120):
    for _ in range(tries):
        if node.proc and node.proc.poll() is not None:
            return False          # process already exited; don't poll a corpse
        try:
            node.rpc_call("getblockchaininfo"); return True
        except Exception:
            time.sleep(0.25)
    return False


def build_network(N, listen_frac):
    teardown()
    # node 0 = attacker; next n_listen = listening; rest = non-listening.
    attacker = Node("A", 0)
    n_listen = max(2, int((N - 1) * listen_frac))
    listen = [Node(f"L{i}", i) for i in range(1, 1 + n_listen)]
    nolisten = [Node(f"U{i}", i) for i in range(1 + n_listen, N)]
    seeds = listen[:min(10, len(listen))]      # backbone entry points

    def backbone(node):
        # every node keeps a couple of persistent links to seed listeners so the
        # graph is connected and addr/chain gossip flows (not to A).
        return [f"-addnode={IP}:{s.p2p}" for s in seeds if s is not node][:2]

    roles = {0: "attacker"}
    plan = []   # (node, args)

    # attacker: listening, advertises, accepts inbound from everyone. It dials the
    # listening nodes crawler-style AFTER startup via the addconnection RPC (-addnode
    # is capped at 8 manual peers, so it can't model a crawler's full outbound set).
    plan.append((attacker, LIGHT + [BIND, "-listen=1", "-maxconnections=700",
                 f"-externalip={IP}:{attacker.p2p}"]))

    for l in listen:
        roles[l.i] = "listening"
        plan.append((l, LIGHT + [BIND, "-listen=1", "-maxconnections=80"] + backbone(l)))

    for u in nolisten:
        roles[u.i] = "non-listening"
        # NAT'd: no inbound. It learned A's advertised address -> dials A.
        plan.append((u, LIGHT + ["-listen=0", "-maxconnections=24",
                     f"-addnode={IP}:{attacker.p2p}"] + backbone(u)))

    return attacker, listen, nolisten, roles, plan


def start_batched(plan):
    started, base = [], mem_available_mb()
    print(f"launching {len(plan)} nodes in batches of {BATCH} "
          f"(MemAvailable start: {base} MB, floor: {RAM_FLOOR_MB} MB)")
    for b in range(0, len(plan), BATCH):
        chunk = plan[b:b + BATCH]
        for node, args in chunk:
            launch(node, args)
        ok = sum(await_rpc(node) for node, _ in chunk)
        avail, rss = mem_available_mb(), bitcoind_rss_mb()
        print(f"  batch {b//BATCH+1:>2}: +{len(chunk)} (rpc up {ok}/{len(chunk)})  "
              f"total {b+len(chunk)}/{len(plan)}  MemAvail {avail} MB  bitcoind RSS {rss} MB")
        for node, _ in chunk:
            started.append(node)
        if avail is not None and avail < RAM_FLOOR_MB:
            print(f"  !! MemAvailable {avail} MB < floor {RAM_FLOOR_MB} MB -- stopping startup here")
            break
    return started


def subver_index(subver):
    m = re.search(r"\(n(\d+)\)", subver or "")
    return int(m.group(1)) if m else None


def _wait(fn, want, tries=120, gap=0.25):
    for _ in range(tries):
        if fn() == want or (callable(want) and want(fn())):
            return True
        time.sleep(gap)
    return False


def run_traffic(attacker, sources, far, n_sources=4, rounds=8, interval=8):
    """Real transaction traffic: a few wallet nodes originate payments on a fixed
    interval; measure how fast each broadcast diffuses to the attacker and to a far
    non-listening node. Shows who-broadcasts-what and the inv-diffusion delay."""
    sources = sources[:n_sources]
    if len(sources) < 2:
        print("  (not enough listening sources for traffic)"); return
    funder = sources[0]
    print(f"\ntraffic: {len(sources)} wallet sources, funder=n{funder.i}, "
          f"1 payment every {interval}s x {rounds} rounds")

    # fund: funder mines to maturity, seeds the other sources
    funder.rpc_call("createwallet", "w")
    faddr = funder.rpc_call("getnewaddress", wallet="w")
    funder.rpc_call("generatetoaddress", 101, faddr, wallet="w")
    _wait(lambda: attacker.rpc_call("getblockchaininfo")["blocks"], 101)
    for s in sources[1:]:
        s.rpc_call("createwallet", "w")
        funder.rpc_call("sendtoaddress", s.rpc_call("getnewaddress", wallet="w"), 1.0, wallet="w")
    funder.rpc_call("generatetoaddress", 1, faddr, wallet="w")
    _wait(lambda: attacker.rpc_call("getblockchaininfo")["blocks"], 102)

    print(f"  {'tx':12}{'source':8}{'->A':>8}{'->far(nonlisten)':>18}")
    for r in range(rounds):
        s = sources[1 + r % (len(sources) - 1)]      # rotate over the funded sources
        dest = s.rpc_call("getnewaddress", wallet="w")
        t0 = time.time()
        txid = s.rpc_call("sendtoaddress", dest, 0.01, wallet="w")
        a_t = far_t = None
        deadline = time.time() + interval + 10
        while time.time() < deadline and (a_t is None or far_t is None):
            if a_t is None and txid in attacker.rpc_call("getrawmempool"):
                a_t = time.time() - t0
            if far_t is None and far and txid in far.rpc_call("getrawmempool"):
                far_t = time.time() - t0
            time.sleep(0.2)
        print(f"  {txid[:10]}..  n{s.i:<6}{(f'{a_t:.1f}s' if a_t else 'miss'):>8}"
              f"{(f'{far_t:.1f}s' if far_t else 'miss'):>18}")
        slept = time.time() - t0
        if slept < interval:
            time.sleep(interval - slept)
    print("  (origin and every relay re-announce each tx to each peer on independent")
    print("   ~2s outbound / ~5s inbound Poisson timers; that spread is the diffusion.)")


def main(N=300, listen_frac=0.35, settle=45, traffic=True):
    print(f"NETWORK SIM  N={N} nodes  listen_frac={listen_frac}")
    print("=" * 70)
    attacker, listen, nolisten, roles, plan = build_network(N, listen_frac)
    print(f"roles: 1 attacker, {len(listen)} listening, {len(nolisten)} non-listening")

    started = start_batched(plan)
    if attacker not in started:
        print("attacker never started; aborting"); return

    # attacker dials a SAMPLE of the listening nodes. A single Core node makes only
    # ~8 outbound-full-relay connections (MAX_OUTBOUND_FULL_RELAY_CONNECTIONS), so it
    # cannot enumerate all listeners -- that is a parallel crawler's job (src/harvest.py
    # opens thousands of one-shot handshakes). The point here is the other direction:
    # the non-listening nodes, which no crawler can reach, dial US.
    live_listen = [l for l in listen if l in started]
    dialed = 0
    for l in live_listen:
        try:
            attacker.rpc_call("addconnection", f"{IP}:{l.p2p}", "outbound-full-relay", True)
            dialed += 1
        except Exception:
            pass          # refused once Core's 8-outbound-full-relay cap is hit
    print(f"attacker dialed {dialed} listening nodes before hitting Core's "
          f"~8-outbound cap (of {len(live_listen)} listeners; the rest are "
          f"crawler-reachable, not Core-outbound-reachable)")

    print(f"\nletting connections form ({settle}s)...")
    peak_rss = bitcoind_rss_mb() or 0
    t0 = time.time()
    while time.time() - t0 < settle:
        time.sleep(5)
        peak_rss = max(peak_rss, bitcoind_rss_mb() or 0)
        try:
            c = attacker.rpc_call("getconnectioncount")
        except Exception:
            c = "?"
        print(f"  t+{int(time.time()-t0):>3}s  A connections: {c}  "
              f"MemAvail {mem_available_mb()} MB  peak bitcoind RSS {peak_rss} MB")

    # who did the attacker end up connected to, by role?
    peers = attacker.rpc_call("getpeerinfo")
    seen = {}   # node index -> inbound?
    for p in peers:
        idx = subver_index(p.get("subver"))
        if idx is not None:
            seen[idx] = p.get("inbound", False)

    live_nolisten = [u for u in nolisten if u in started]
    cap_listen = sum(1 for l in live_listen if l.i in seen)
    cap_nolisten = sum(1 for u in live_nolisten if u.i in seen)
    inbound_nolisten = sum(1 for u in live_nolisten if seen.get(u.i) is True)

    print("\n" + "=" * 70)
    print("RESULT")
    print(f"  nodes up                 : {len(started)}/{len(plan)}")
    print(f"  A total peers            : {len(peers)}")
    print(f"  listening nodes (n={len(live_listen)})    : crawler-reachable; A connects to a "
          f"{cap_listen}-node sample (Core's ~8-outbound cap)")
    print(f"  NON-LISTENING captured   : {cap_nolisten}/{len(live_nolisten)}  "
          f"({inbound_nolisten} dialed A -- the only way to observe them)")
    print(f"  peak bitcoind RSS        : {peak_rss} MB   MemAvailable now: {mem_available_mb()} MB")
    print("\n  Non-listening nodes accept no inbound, so no crawler can reach them.")
    print("  They are visible here only because they dialed the advertised attacker.")

    if traffic and live_listen:
        far = next((u for u in live_nolisten if u.i in seen), None)
        run_traffic(attacker, live_listen, far)
        peak_rss = max(peak_rss, bitcoind_rss_mb() or 0)
        print(f"\n  peak bitcoind RSS incl. traffic: {peak_rss} MB   "
              f"MemAvailable now: {mem_available_mb()} MB")

    print("\ntearing down...")
    for node in started:
        try:
            node.rpc_call("stop")
        except Exception:
            if node.proc:
                node.proc.send_signal(signal.SIGTERM)
    for node in started:
        if node.proc:
            try:
                node.proc.wait(timeout=20)
            except Exception:
                node.proc.kill()
    teardown()


if __name__ == "__main__":
    N = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    frac = float(sys.argv[2]) if len(sys.argv) > 2 else 0.35
    settle = int(sys.argv[3]) if len(sys.argv) > 3 else 45
    main(N, frac, settle)
