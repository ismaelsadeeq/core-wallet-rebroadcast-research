#!/usr/bin/env python3
"""Full Tier-2 pipeline: observe inv -> getdata the tx from the announcing peer
-> compute txid locally (inv carries wtxid under BIP339) -> fingerprint wallet
-> join with the announcer's OS/ASN.

Usage: python3 observer_wallet.py <targets_file> <duration_s> [max_peers]
"""
import sys, os, socket, time, threading, io, struct, json
import xml.etree.ElementTree as ET
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # src/ (for peer_probe)
# wallet fingerprinting lives in a separate repo (Ishaana Misra); point at it via env:
#   WALLET_FP_PATH=/path/to/wallet-fingerprinting
WALLET_FP_PATH = os.environ.get("WALLET_FP_PATH")
if WALLET_FP_PATH:
    sys.path.insert(0, WALLET_FP_PATH)
    sys.path.insert(0, os.path.join(WALLET_FP_PATH, "tqdm_shim"))
import peer_probe as pp

MSG_TX, MSG_WTX = 1, 5


def parse_and_ids(raw):
    """Return (wtxid_hex, txid_hex) from a raw (possibly segwit) tx."""
    f = io.BytesIO(raw)
    version = f.read(4)
    pos = f.tell()
    b = f.read(2)
    segwit = len(b) == 2 and b[0] == 0x00 and b[1] == 0x01
    if not segwit:
        f.seek(pos)
    cs = pp.deser_compactsize
    nin = cs(f); inputs = []
    for _ in range(nin):
        prevout = f.read(36); sl = cs(f); scr = f.read(sl); seq = f.read(4)
        inputs.append((prevout, sl, scr, seq))
    nout = cs(f); outs = []
    for _ in range(nout):
        val = f.read(8); sl = cs(f); spk = f.read(sl); outs.append((val, sl, spk))
    if segwit:
        for _ in range(nin):
            for _ in range(cs(f)):
                f.read(cs(f))
    locktime = f.read(4)
    sc = pp.ser_compactsize
    legacy = version + sc(nin)
    for prevout, sl, scr, seq in inputs:
        legacy += prevout + sc(sl) + scr + seq
    legacy += sc(nout)
    for val, sl, spk in outs:
        legacy += val + sc(sl) + spk
    legacy += locktime
    wtxid = pp.sha256d(raw)[::-1].hex()
    txid = pp.sha256d(legacy)[::-1].hex()
    return wtxid, txid


def observe(ip, port, deadline, st, lock):
    try:
        sock = socket.create_connection((ip, port), timeout=8); sock.settimeout(8)
        rd = pp._reader(sock)
        sock.sendall(pp.make_message("version", pp.build_version_payload(
            services=pp.NODE_WITNESS, relay=True, timestamp=int(time.time()))))
        got = False
        while time.monotonic() < deadline:
            c, p = pp.parse_message(rd)
            if c == "ping": sock.sendall(pp.make_message("pong", p)); continue
            if c == "version": got = True
            if c == "verack": break
        if not got: return
        sock.sendall(pp.make_message("verack", b""))
        while time.monotonic() < deadline:
            c, p = pp.parse_message(rd)
            if c == "ping":
                sock.sendall(pp.make_message("pong", p)); continue
            if c == "inv":
                f = io.BytesIO(p); n = pp.deser_compactsize(f); want = []
                ts = time.monotonic()
                for _ in range(n):
                    typ = struct.unpack("<I", f.read(4))[0]; h = f.read(32)
                    if typ in (MSG_TX, MSG_WTX):
                        key = h[::-1].hex()
                        with lock:
                            if key not in st["first"]:
                                st["first"][key] = (ip, ts)
                                want.append((typ, h))
                if want:
                    sock.sendall(pp.make_message("getdata", pp.build_getdata_payload(want)))
            elif c == "tx":
                try:
                    wt, tx = parse_and_ids(p)
                    with lock:
                        st["txid"][wt] = tx
                        st["served"][wt] = ip
                except Exception:
                    pass
    except Exception:
        return
    finally:
        try: sock.close()
        except Exception: pass


def main():
    tf, dur = sys.argv[1], float(sys.argv[2])
    maxp = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    targets = []
    for line in open(tf):
        line = line.strip()
        if line:
            ip, port = (line.rsplit(":", 1) + ["8333"])[:2]; targets.append((ip, int(port)))
    targets = targets[:maxp]
    st = {"first": {}, "txid": {}, "served": {}}; lock = threading.Lock()
    dl = time.monotonic() + dur
    ths = [threading.Thread(target=observe, args=(ip, p, dl, st, lock), daemon=True) for ip, p in targets]
    for t in ths: t.start()
    for t in ths: t.join(timeout=dur + 10)

    print(f"peers announcing: {len(set(v[0] for v in st['first'].values()))}/{len(targets)}")
    print(f"distinct inv hashes seen: {len(st['first'])};  txs fetched via getdata: {len(st['txid'])}")
    served_also_announced = sum(1 for wt in st["txid"] if st["served"].get(wt) == st["first"].get(wt, (None,))[0])
    print(f"announcer ALSO served the tx on getdata (attribution bit): {served_also_announced}/{len(st['txid'])}")

    # enrichment maps
    raw = json.load(open("/tmp/raw_census.json"))
    asn_by_ip = {e["address"]: e.get("mapped_as") for t in ("new", "tried") for e in raw.get(t, {}).values()}
    osm = {}
    for h in ET.parse("/tmp/census_os.xml").getroot().findall("host"):
        ipel = h.find("address[@addrtype='ipv4']"); o = h.find("os")
        if ipel is not None and o is not None:
            m = o.findall("osmatch")
            if m and int(m[0].get("accuracy", "0")) >= 70: osm[ipel.get("addr")] = m[0].get("name")

    json.dump({"first": st["first"], "txid": st["txid"], "served": st["served"]},
              open("/tmp/obs_wallet_out.json", "w"))  # persist before enrichment
    if WALLET_FP_PATH:
        os.chdir(WALLET_FP_PATH)   # for rpc_config.ini
    from fingerprinting import detect_wallet, module
    def norm(w): return "|".join(sorted(w)) if isinstance(w, (set, list)) else str(w)
    wdist = Counter(); joined = []
    for i, (wt, txid) in enumerate(list(st["txid"].items())[:60]):
        try: w = norm(detect_wallet(module.get_tx(txid))[0])
        except Exception: w = "fetch_fail"
        wdist[w] += 1
        ann = st["first"].get(wt, ("?",))[0]
        if w not in ("fetch_fail", "Other", "Unclear", ""):
            joined.append((txid[:12], w, ann, asn_by_ip.get(ann), osm.get(ann, "-")))

    print("\nwallet distribution (observed+fetched txs):", dict(wdist.most_common()))
    print(f"\nwallet x first-announcer (ASN, OS):")
    print(f"{'txid':<13}{'wallet':<16}{'announcer':<17}{'ASN':<9}{'OS'}")
    for txid, w, ann, asn, os in joined[:25]:
        print(f"{txid:<13}{w[:15]:<16}{ann:<17}AS{str(asn):<7}{(os or '-')[:26]}")
    json.dump({"first": st["first"], "txid": st["txid"], "served": st["served"]},
              open("/tmp/obs_wallet_out.json", "w"))


if __name__ == "__main__":
    main()
