#!/usr/bin/env python3
"""Regtest-magic P2P observers for the deanon sim (layer 2).

An observer opens a relay-ON connection to a node and records EVERY tx/wtx
announcement as (txid, from_node, monotonic_ts). Two roles:
  spy     — connected directly to the ORIGIN (sees the origin's own announcements
            and, later, each rebroadcast).
  passive — connected to non-origin relays (sees only the diffusion wavefront).

Built on peer_probe primitives with the regtest magic. Runs inside the lab
container alongside the nodes (all on 127.0.0.1).
"""
from __future__ import annotations
import io, socket, struct, threading, time
import peer_probe as pp

MSG_TX, MSG_WTX = 1, 5
REGTEST_MAGIC = bytes.fromhex("fabfb5da")


def observe(node_name, ip, port, deadline, sink, lock, *, magic=REGTEST_MAGIC):
    """Relay-ON connection; append (txid_hex, node_name, ts) per announced tx."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=6)
        sock.settimeout(6)
        rd = pp._reader(sock)
        ver = pp.build_version_payload(services=pp.NODE_WITNESS,
                                       user_agent="/deanon-observer:0.1/",
                                       timestamp=int(time.time()), relay=True)
        sock.sendall(pp.make_message("version", ver, magic=magic))
        got_ver = False
        while time.monotonic() < deadline:
            cmd, payload = pp.parse_message(rd, magic=magic)
            if cmd == "ping":
                sock.sendall(pp.make_message("pong", payload, magic=magic)); continue
            if cmd == "version": got_ver = True
            if cmd == "verack": break
        if not got_ver:
            return
        sock.sendall(pp.make_message("verack", b"", magic=magic))
        # listen for inv announcements
        while time.monotonic() < deadline:
            try:
                cmd, payload = pp.parse_message(rd, magic=magic)
            except (socket.timeout, TimeoutError):
                continue
            if cmd == "ping":
                sock.sendall(pp.make_message("pong", payload, magic=magic)); continue
            if cmd != "inv":
                continue
            f = io.BytesIO(payload)
            n = pp.deser_compactsize(f)
            ts = time.monotonic()
            rows = []
            for _ in range(n):
                typ = struct.unpack("<I", f.read(4))[0]
                h = f.read(32)
                if typ in (MSG_TX, MSG_WTX):
                    rows.append((h[::-1].hex(), node_name, ts))
            if rows:
                with lock:
                    sink.extend(rows)
    except Exception:
        return
    finally:
        if sock is not None:
            try: sock.close()
            except Exception: pass


class ObserverSet:
    """Runs several observers concurrently for a window; collects announcements."""
    def __init__(self):
        self.sink = []          # list of (txid, from_node, ts)
        self.lock = threading.Lock()
        self.threads = []
        self.t0 = None

    def start(self, roles, duration):
        """roles: list of (role, node_name, ip, port). role in {spy, passive}."""
        self.t0 = time.monotonic()
        deadline = self.t0 + duration
        self.role_of = {}
        for role, name, ip, port in roles:
            self.role_of[name] = role
            t = threading.Thread(target=observe,
                                 args=(name, ip, port, deadline, self.sink, self.lock),
                                 daemon=True)
            t.start()
            self.threads.append(t)
        return self

    def join(self):
        for t in self.threads:
            t.join(timeout=5)

    def announcements(self, txid):
        """All (from_node, role, dt_seconds) for a txid, time-ordered."""
        with self.lock:
            rows = [(fn, self.role_of.get(fn, "?"), ts - self.t0)
                    for (tx, fn, ts) in self.sink if tx == txid]
        return sorted(rows, key=lambda r: r[2])

    def first_by_role(self, txid):
        """Earliest announcement per role: {role: (from_node, dt)}."""
        out = {}
        for fn, role, dt in self.announcements(txid):
            if role not in out:
                out[role] = (fn, dt)
        return out
