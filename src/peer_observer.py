#!/usr/bin/env python3
"""peer_observer — first-spy / diffusion source-inference instrument.

Holds many concurrent connections (relay ON), records the FIRST peer to announce
each txid and when. This is the measurement core for A4-style source estimators
and for evaluating relay-privacy defenses (Dandelion, private broadcast).

Usage:
    python3 peer_observer.py <targets_file> <duration_seconds> [max_peers]

ETHICS/SCOPE: for anonymity *measurement* and defense *evaluation*. The intended
experiment broadcasts YOUR OWN marked txs (ground truth) and checks whether this
observer can localize you as source with vs without private broadcast — not
pointed at third-party payments.
"""
import sys, socket, time, threading, io, struct
import peer_probe as pp

MSG_TX, MSG_WTX = 1, 5


def observe(ip, port, deadline, sink, lock, user_agent=pp.PROBE_USER_AGENT):
    """Connect with relay ON; append (txid_hex, ip, monotonic_ts) for each inv'd tx."""
    try:
        sock = socket.create_connection((ip, port), timeout=8)
        sock.settimeout(8)
        rd = pp._reader(sock)
        ver = pp.build_version_payload(services=pp.NODE_WITNESS, user_agent=user_agent,
                                       timestamp=int(time.time()), relay=True)  # relay ON
        sock.sendall(pp.make_message("version", ver))
        # finish handshake (drain to verack, answer pings)
        got_ver = False
        while time.monotonic() < deadline:
            cmd, payload = pp.parse_message(rd)
            if cmd == "ping": sock.sendall(pp.make_message("pong", payload)); continue
            if cmd == "version": got_ver = True
            if cmd == "verack": break
        if not got_ver:
            return
        sock.sendall(pp.make_message("verack", b""))
        # observe inv announcements
        while time.monotonic() < deadline:
            cmd, payload = pp.parse_message(rd)
            if cmd == "ping":
                sock.sendall(pp.make_message("pong", payload)); continue
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
                    rows.append((h[::-1].hex(), ip, ts))  # display byte order
            if rows:
                with lock:
                    sink.extend(rows)
    except Exception:
        return
    finally:
        try: sock.close()
        except Exception: pass


def main():
    targets_file, duration = sys.argv[1], float(sys.argv[2])
    max_peers = int(sys.argv[3]) if len(sys.argv) > 3 else 40
    targets = []
    for line in open(targets_file):
        line = line.strip()
        if not line: continue
        ip, port = (line.rsplit(":", 1) + ["8333"])[:2]
        targets.append((ip, int(port)))
    targets = targets[:max_peers]
    sink, lock = [], threading.Lock()
    deadline = time.monotonic() + duration
    threads = [threading.Thread(target=observe, args=(ip, p, deadline, sink, lock), daemon=True)
               for ip, p in targets]
    for t in threads: t.start()
    for t in threads: t.join(timeout=duration + 10)

    # aggregate: first-seen peer per txid (the first-spy estimate)
    first = {}
    for txid, ip, ts in sink:
        if txid not in first or ts < first[txid][1]:
            first[txid] = (ip, ts)
    from collections import Counter
    announcer = Counter(ip for ip, _ in first.values())
    print(f"peers observed: {len(set(ip for _,ip,_ in sink))}/{len(targets)}")
    print(f"total inv rows: {len(sink)};  distinct txids: {len(first)}")
    print(f"\ntop 'first-announcer' peers (closest-to-source / best-connected in our view):")
    for ip, c in announcer.most_common(12):
        print(f"  {ip:22} first to announce {c:4} txs ({100*c//max(1,len(first))}%)")
    import json
    json.dump({"first_seen": {k: [v[0], v[1]] for k, v in first.items()}},
              open("/tmp/observer_out.json", "w"))
    print("\n[saved] /tmp/observer_out.json")


if __name__ == "__main__":
    main()
