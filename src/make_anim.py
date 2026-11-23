#!/usr/bin/env python3
"""Generate animated GIFs for the report: diffusion, rebroadcast attack, NAT capture.

Renders frame by frame with Pillow.  No display needed.
Output: results/figures/*.gif

Usage:  nix-shell -p python3Packages.pillow dejavu_fonts --run "python3 src/make_anim.py"
        (dejavu_fonts gives a real TrueType monospace; without it the text falls back
         to Pillow's scalable default font, which is still readable.)
"""
from __future__ import annotations
import math, random, os

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIGDIR = os.path.join(HERE, "results", "figures")
os.makedirs(FIGDIR, exist_ok=True)

random.seed(42)  # reproducible layouts
TAU = 2 * math.pi

# ─── palette (3Blue1Brown / Manim, matching svgplot.py) ──────
BG      = (13, 17, 23)
FAINT   = (34, 42, 53)
GREY    = (99, 110, 123)
TEXT    = (201, 212, 224)
BLUE    = (88, 196, 221)     # #58c4dd  3b1b blue
ORANGE  = (240, 172, 95)     # #f0ac5f  gold
GREEN   = (131, 193, 103)    # #83c167
RED     = (252, 98, 85)      # #fc6255
PURPLE  = (166, 127, 214)    # #a67fd6
YELLOW  = (245, 213, 71)     # #f5d547

W, H = 1200, 700
FPS = 10

RB_LEG = [(ORANGE, "the node", "node"), (PURPLE, "spy", "node"),
          (PURPLE, "spy connection", "line"), (YELLOW, "announcement", "line"),
          (RED, "lone rebroadcast", "line")]


def dist(a, b):
    return math.hypot(a[0]-b[0], a[1]-b[1])


def lerp(a, b, t):
    return (a[0]+(b[0]-a[0])*t, a[1]+(b[1]-a[1])*t)


def poisson(mean):
    return -mean * math.log(1 - random.random())


SS = 3  # supersampling factor for sharp text and smooth edges


def circle(draw, x, y, r, color, outline=None):
    x, y, r = x*SS, y*SS, r*SS
    draw.ellipse([x-r, y-r, x+r, y+r], fill=color, outline=outline)


def line(draw, a, b, color, width=1):
    draw.line([a[0]*SS, a[1]*SS, b[0]*SS, b[1]*SS], fill=color, width=max(1, width*SS))


_font_cache = {}
_font_paths = None
def _find_fonts():
    """Locate a real TrueType monospace; NixOS has no /usr/share/fonts."""
    global _font_paths
    if _font_paths is None:
        import glob
        pats = ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                "/run/current-system/sw/share/X11/fonts/DejaVuSansMono.ttf"]
        for base in ("/nix/store/*dejavu*", "/nix/store/*/share/fonts"):
            pats += glob.glob(base + "/**/DejaVuSansMono.ttf", recursive=True)
            pats += glob.glob(base + "/**/DejaVuSans.ttf", recursive=True)
        _font_paths = pats
    return _font_paths

def text(draw, x, y, s, color=TEXT, anchor="mm", size=26):
    key = size * SS
    if key not in _font_cache:
        font = None
        for p in _find_fonts():
            try:
                font = ImageFont.truetype(p, key); break
            except OSError:
                continue
        if font is None:                       # Pillow >=10.1 scales the default font
            try:
                font = ImageFont.load_default(size=key)
            except TypeError:
                font = ImageFont.load_default()
        _font_cache[key] = font
    draw.text((x*SS, y*SS), s, fill=color, font=_font_cache[key], anchor=anchor)


def legend(draw, items, x=28, y=74):
    """Small key in the top-left: items are (color, label, 'node'|'line')."""
    for color, label, kind in items:
        if kind == "line":
            line(draw, (x, y), (x+30, y), color, 4)
        else:
            circle(draw, x+15, y, 7, color)
        text(draw, x+42, y, label, TEXT, anchor="lm", size=19)
        y += 30


def _new_frame():
    """Create a supersampled frame."""
    return Image.new("RGB", (W*SS, H*SS), BG)


def _finish_frame(img):
    """Downscale supersampled frame to final size (anti-aliased)."""
    return img.resize((W, H), Image.LANCZOS)


def save_gif(frames, path, duration_ms=230):
    """Save list of PIL Images as an animated GIF."""
    frames[0].save(path, save_all=True, append_images=frames[1:],
                   duration=duration_ms, loop=0, optimize=False)
    print(f"  [gif] {os.path.basename(path)}  ({len(frames)} frames, {len(frames)*duration_ms/1000:.1f}s)")


# ═══════════════════════════════════════════════════════════════
# 1. DIFFUSION — Poisson-timer tx propagation
# ═══════════════════════════════════════════════════════════════
def make_diffusion():
    N = 20
    cx, cy = W//2, H//2
    # place nodes
    pos = []
    for i in range(N):
        a = TAU * i / N
        r = random.uniform(150, 260)
        if i < 5:
            r = random.uniform(60, 120)
        pos.append((cx + r*math.cos(a) + random.uniform(-20,20),
                     cy + r*math.sin(a) + random.uniform(-20,20)))
    # edges: nearest 2-3 peers
    edges = set()
    for i in range(N):
        by_d = sorted(range(N), key=lambda j: dist(pos[i], pos[j]))
        for j in by_d[1:4]:
            edges.add((min(i,j), max(i,j)))
    edges = list(edges)

    SRC = N - 3
    OBS = N // 2
    # BFS with Poisson delays
    hear_time = [float('inf')] * N
    hear_from = [-1] * N
    hear_time[SRC] = 0.0
    queue = [SRC]
    while queue:
        cur = queue.pop(0)
        for a, b in edges:
            peer = b if a == cur else (a if b == cur else -1)
            if peer < 0:
                continue
            delay = poisson(3.0 if cur == SRC else 4.0)
            arr = hear_time[cur] + delay
            if arr < hear_time[peer]:
                hear_time[peer] = arr
                hear_from[peer] = cur
                queue.append(peer)

    max_t = max(t for t in hear_time if t < float('inf')) + 2.0
    n_frames = int(max_t * FPS) + FPS * 2  # extra 2s at end
    frames = []

    for fi in range(n_frames):
        t = fi / FPS
        img = _new_frame()
        draw = ImageDraw.Draw(img)
        # title
        text(draw, W//2, 40, "Diffusion: the source is only probably first", TEXT, size=30)
        legend(draw, [(ORANGE, "source", "node"), (GREEN, "observer", "node"),
                      (BLUE, "heard the tx", "node"), (GREY, "not yet", "node"),
                      (ORANGE, "tx in flight", "line")])
        # edges
        for a, b in edges:
            line(draw, pos[a], pos[b], FAINT)
        # packets in flight
        for i in range(N):
            fr = hear_from[i]
            if fr >= 0 and t > hear_time[fr] and t < hear_time[i]:
                prog = (t - hear_time[fr]) / (hear_time[i] - hear_time[fr])
                p = lerp(pos[fr], pos[i], min(1, prog))
                circle(draw, p[0], p[1], 4, ORANGE)
        # nodes
        for i in range(N):
            heard = t >= hear_time[i]
            if i == SRC:
                color = ORANGE
            elif i == OBS:
                color = GREEN
            elif heard:
                color = BLUE
            else:
                color = GREY
            r = 12 if i in (SRC, OBS) else 8
            circle(draw, pos[i][0], pos[i][1], r, color)
        text(draw, pos[SRC][0], pos[SRC][1]+26, "SOURCE", ORANGE, size=24)
        text(draw, pos[OBS][0], pos[OBS][1]+26, "OBSERVER", GREEN, size=24)
        # status line
        obs_heard = t >= hear_time[OBS]
        if obs_heard:
            fr = hear_from[OBS]
            who = "the source" if fr == SRC else "a relay, not the source"
            text(draw, W//2, H-34, f"observer heard it first from {who}", YELLOW, size=27)
        else:
            text(draw, W//2, H-34, "the observer is still waiting", TEXT, size=27)
        frames.append(_finish_frame(img))

    # hold last frame
    for _ in range(FPS * 4):
        frames.append(frames[-1])
    save_gif(frames, os.path.join(FIGDIR, "diffusion.gif"))


# ═══════════════════════════════════════════════════════════════
# 2. REBROADCAST ATTACK — planted tx attribution
# ═══════════════════════════════════════════════════════════════
def make_rebroadcast():
    """Two-act story: diffusion protects privacy, then rebroadcast breaks it."""
    cx, cy = W//2, H//2

    # Network layout: 8 nodes in a ring, spy in the CENTER connected to ALL
    N = 8
    nodes = []
    for i in range(N):
        a = TAU * i / N - TAU/4  # start from top
        nodes.append((cx + 220*math.cos(a), cy + 180*math.sin(a)))
    NODE = 0     # the node the spy is trying to identify (same node both acts)
    SPY_POS = (cx, cy)  # spy at center — connected to everyone

    # edges: ring + some cross connections
    edges = [(i, (i+1) % N) for i in range(N)]
    edges += [(0, 3), (1, 5), (2, 6)]

    # BFS diffusion from NODE (it sends a tx in Act 1)
    hear_time = [float('inf')] * N
    hear_from = [-1] * N
    hear_time[NODE] = 0
    q = [NODE]
    while q:
        cur = q.pop(0)
        for a, b in edges:
            peer = b if a == cur else (a if b == cur else -1)
            if peer < 0: continue
            delay = poisson(3.0)
            arr = hear_time[cur] + delay
            if arr < hear_time[peer]:
                hear_time[peer] = arr; hear_from[peer] = cur; q.append(peer)
    max_diff = max(t for t in hear_time if t < float('inf'))
    # Each node announces to the spy on its OWN Poisson timer (not instantly).
    # This means the source doesn't necessarily announce first to the spy.
    spy_hear = [hear_time[i] + poisson(2.5) for i in range(N)]
    first_to_spy = min(range(N), key=lambda i: spy_hear[i])

    frames = []

    def draw_spy_connections(draw, highlight_node=None):
        """Draw spy connections to all nodes (faint, or highlighted to one)."""
        for i in range(N):
            col = GREEN if i == highlight_node else PURPLE
            w = 2 if i == highlight_node else 1
            line(draw, SPY_POS, nodes[i], (*col, 60) if i != highlight_node else col, w)

    # --- ACT 1: The node sends a tx. Spy sees it from everyone. ---

    # 1a: setup — show spy connected to ALL nodes
    for fi in range(FPS * 2):
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 40, "ACT 1: The node sends a transaction", BLUE)
        for a, b in edges: line(draw, nodes[a], nodes[b], FAINT)
        legend(draw, RB_LEG)
        draw_spy_connections(draw)
        for i in range(N):
            col = ORANGE if i == NODE else BLUE
            circle(draw, nodes[i][0], nodes[i][1], 8, col)
        text(draw, nodes[NODE][0], nodes[NODE][1]-28, "THE NODE", ORANGE, size=22)
        circle(draw, SPY_POS[0], SPY_POS[1], 10, PURPLE)
        text(draw, SPY_POS[0], SPY_POS[1]+30, "SPY",PURPLE)
        text(draw, W//2, H-34, "the spy is connected to every node", TEXT)
        frames.append(_finish_frame(img))

    # 1b: diffusion — spy sees tx arrive from MULTIPLE nodes
    span = max(spy_hear)
    nb = FPS * 4
    for fi in range(nb):
        dt = (fi / nb) * (span + 1.0)
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 40, "ACT 1: Tx diffuses — spy hears it from many nodes", BLUE)
        for a, b in edges: line(draw, nodes[a], nodes[b], FAINT)
        legend(draw, RB_LEG)
        draw_spy_connections(draw)
        # packets between peers
        for i in range(N):
            fr = hear_from[i]
            if fr >= 0 and dt > hear_time[fr] and dt < hear_time[i]:
                prog = (dt - hear_time[fr]) / (hear_time[i] - hear_time[fr])
                p = lerp(nodes[fr], nodes[i], min(1, prog))
                circle(draw, p[0], p[1], 5, ORANGE)
        # packets from nodes to spy (each on its own Poisson timer)
        for i in range(N):
            announce_start = spy_hear[i] - 1.5  # visual travel time
            if dt >= announce_start and dt < spy_hear[i]:
                prog = (dt - announce_start) / 1.5
                p = lerp(nodes[i], SPY_POS, min(1, prog))
                circle(draw, p[0], p[1], 5, YELLOW)
        # count how many the spy heard from
        heard_count = sum(1 for i in range(N) if dt >= spy_hear[i])
        for i in range(N):
            heard = dt >= hear_time[i]
            col = ORANGE if i == NODE else BLUE if heard else GREY
            circle(draw, nodes[i][0], nodes[i][1], 8, col)
        text(draw, nodes[NODE][0], nodes[NODE][1]-28, "THE NODE", ORANGE, size=22)
        circle(draw, SPY_POS[0], SPY_POS[1], 10, PURPLE)
        text(draw, SPY_POS[0], SPY_POS[1]+30, "SPY",PURPLE)
        if heard_count >= N:
            first_label = "THE NODE" if first_to_spy == NODE else f"a relay, not the source"
            text(draw, W//2, H-34, f"first to reach the spy: {first_label}", YELLOW)
        elif heard_count > 0:
            text(draw, W//2, H-34, f"spy has heard from {heard_count}/{N} nodes", YELLOW)
        else:
            text(draw, W//2, H-34, "the tx spreads node to node", TEXT)
        frames.append(_finish_frame(img))

    # 1c: result — spy heard from everyone, can't tell who's the source
    for fi in range(FPS * 3):
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 40, "ACT 1 RESULT: Spy heard from ALL nodes — can't find source", GREEN)
        for a, b in edges: line(draw, nodes[a], nodes[b], FAINT)
        legend(draw, RB_LEG)
        draw_spy_connections(draw)
        for i in range(N): circle(draw, nodes[i][0], nodes[i][1], 8, BLUE)
        circle(draw, nodes[NODE][0], nodes[NODE][1], 8, ORANGE)
        text(draw, nodes[NODE][0], nodes[NODE][1]-28, "THE NODE", ORANGE, size=22)
        circle(draw, SPY_POS[0], SPY_POS[1], 10, PURPLE)
        text(draw, SPY_POS[0], SPY_POS[1]+30, "SPY",PURPLE)
        text(draw, W//2, H-34, "diffusion hides the source — privacy holds", GREEN, size=26)
        frames.append(_finish_frame(img))

    # --- ACT 2: Spy plants a tx. Rebroadcast reveals the node. ---

    # 2a: spy plants low-fee tx to the node's address
    for fi in range(FPS * 3):
        t = fi / FPS
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 40, "ACT 2: Spy plants a low-fee tx to the node's address", RED)
        for a, b in edges: line(draw, nodes[a], nodes[b], FAINT)
        legend(draw, RB_LEG)
        draw_spy_connections(draw)
        for i in range(N):
            col = ORANGE if i == NODE else BLUE
            circle(draw, nodes[i][0], nodes[i][1], 8, col)
        text(draw, nodes[NODE][0], nodes[NODE][1]-28, "THE NODE", ORANGE, size=22)
        circle(draw, SPY_POS[0], SPY_POS[1], 10, PURPLE)
        text(draw, SPY_POS[0], SPY_POS[1]+30, "SPY",PURPLE)
        prog = min(1, t / 2.0)
        p = lerp(SPY_POS, nodes[NODE], prog)
        circle(draw, p[0], p[1], 5, YELLOW)
        if t > 2:
            text(draw, nodes[NODE][0]+25, nodes[NODE][1]+18, "holds tx", YELLOW, size=22)
        text(draw, W//2, H-34, "low fee — it won't confirm, so the wallet keeps it", TEXT)
        frames.append(_finish_frame(img))

    # 2b: time passes — spy still connected to all, waiting
    for fi in range(FPS * 2):
        t = fi / FPS
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 40, "ACT 2: 12-36 hours pass... spy waits", TEXT)
        for a, b in edges: line(draw, nodes[a], nodes[b], FAINT)
        legend(draw, RB_LEG)
        draw_spy_connections(draw)
        for i in range(N):
            col = ORANGE if i == NODE else GREY
            circle(draw, nodes[i][0], nodes[i][1], 8, col)
        text(draw, nodes[NODE][0]+25, nodes[NODE][1]+18, "holds tx", YELLOW)
        circle(draw, SPY_POS[0], SPY_POS[1], 10, PURPLE)
        text(draw, SPY_POS[0], SPY_POS[1]+30, "SPY",PURPLE)
        dots = "." * (int(t * 2) % 4)
        text(draw, W//2, H-34, f"the spy waits for a rebroadcast{dots}", TEXT)
        frames.append(_finish_frame(img))

    # 2c: ONLY the node rebroadcasts → spy sees it from exactly one connection
    for fi in range(FPS * 4):
        t = fi / FPS
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 40, "ACT 2: Only THE NODE rebroadcasts — nobody else does", RED)
        for a, b in edges: line(draw, nodes[a], nodes[b], FAINT)
        legend(draw, RB_LEG)
        draw_spy_connections(draw, highlight_node=NODE)
        for i in range(N):
            col = ORANGE if i == NODE else BLUE
            circle(draw, nodes[i][0], nodes[i][1], 8, col)
        text(draw, nodes[NODE][0], nodes[NODE][1]-28, "THE NODE", ORANGE, size=22)
        circle(draw, SPY_POS[0], SPY_POS[1], 10, PURPLE)
        text(draw, SPY_POS[0], SPY_POS[1]+30, "SPY",PURPLE)
        # only one packet: from the node to spy
        prog = min(1, t / 2.0)
        p = lerp(nodes[NODE], SPY_POS, prog)
        circle(draw, p[0], p[1], 6, RED)
        text(draw, W//2, H-34, "only the holder rebroadcasts — 1 of 8 connections", GREEN, size=26)
        frames.append(_finish_frame(img))

    # 2d: result — address linked to node
    for fi in range(FPS * 4):
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 40, "RESULT: the address is pinned to a node IP", GREEN)
        for a, b in edges: line(draw, nodes[a], nodes[b], FAINT)
        legend(draw, RB_LEG)
        draw_spy_connections(draw, highlight_node=NODE)
        for i in range(N):
            col = ORANGE if i == NODE else GREY
            circle(draw, nodes[i][0], nodes[i][1], 8, col)
        circle(draw, nodes[NODE][0], nodes[NODE][1], 16, None, GREEN)
        text(draw, nodes[NODE][0], nodes[NODE][1]-28, "THE NODE", ORANGE, size=22)
        circle(draw, SPY_POS[0], SPY_POS[1], 10, GREEN)
        text(draw, SPY_POS[0], SPY_POS[1]+30, "SPY",GREEN)
        text(draw, W//2, H-34, "on-chain address → node IP", GREEN, size=26)
        frames.append(_finish_frame(img))

    save_gif(frames, os.path.join(FIGDIR, "rebroadcast_attack.gif"))


# ═══════════════════════════════════════════════════════════════
# 3. NAT CAPTURE — non-listening nodes dial the attacker
# ═══════════════════════════════════════════════════════════════
def make_nat_capture():
    """One point: LinkingLion aggressively relays its OWN address, peers gossip it
    onward, and so it ends up connected to nearly everyone — including the
    non-listening (NAT'd) majority, which learns the address and dials back in."""
    cx, cy = W//2, H//2
    ATT = 0
    N_LISTEN, N_NAT = 10, 18
    N = 1 + N_LISTEN + N_NAT
    LIS = range(1, 1 + N_LISTEN)
    NAT = range(1 + N_LISTEN, N)

    pos = [None] * N
    pos[ATT] = (cx, cy)
    for k, i in enumerate(LIS):
        a = TAU * k / N_LISTEN - TAU/4
        r = random.uniform(120, 155)
        pos[i] = (cx + r*math.cos(a), cy + r*math.sin(a))
    for k, i in enumerate(NAT):
        a = TAU * k / N_NAT + 0.12
        r = random.uniform(235, 300)
        pos[i] = (cx + r*math.cos(a), cy + r*math.sin(a))

    # structural edges: attacker<->some listeners, a listener backbone, and each
    # NAT node's own outbound links to its 2 nearest listeners (how gossip reaches it).
    edges = set()
    for i in list(LIS)[:7]:
        edges.add((ATT, i))
    L = list(LIS)
    for k in range(N_LISTEN):
        edges.add((L[k], L[(k+1) % N_LISTEN]))
    edges.add((L[0], L[4])); edges.add((L[2], L[7]))
    for i in NAT:
        for j in sorted(LIS, key=lambda j: dist(pos[i], pos[j]))[:2]:
            edges.add((min(i, j), max(i, j)))
    edges = list(edges)

    g = {i: [] for i in range(N)}
    for a, b in edges:
        g[a].append(b); g[b].append(a)

    def bfs(src, mean):                              # address gossip, hop by hop
        ht = [float('inf')] * N; hf = [-1] * N; ht[src] = 0.0; q = [src]
        while q:
            cur = q.pop(0)
            for p in g[cur]:
                arr = ht[cur] + poisson(mean)
                if arr < ht[p]:
                    ht[p] = arr; hf[p] = cur; q.append(p)
        return ht, hf

    TRAVEL = 0.55
    learn_t, learn_f = bfs(ATT, 1.1)
    dial_t = {i: learn_t[i] + random.uniform(0.8, 2.0) for i in NAT}
    end = max(dial_t.values()) + 2.5

    LEG = [(ORANGE, "LinkingLion", "node"), (PURPLE, "has its address", "node"),
           (GREEN, "captured (inbound)", "node"), (GREY, "not reached yet", "node"),
           (PURPLE, "address being gossiped", "line"), (GREEN, "inbound connection", "line"),
           (GREY, "existing peer link", "line")]

    frames = []
    nf = int(end * FPS) + FPS * 3
    for fi in range(nf):
        t = fi / FPS
        img = _new_frame(); draw = ImageDraw.Draw(img)

        for a, b in edges:                           # existing peer links, faint
            line(draw, pos[a], pos[b], FAINT, 1)

        captured = 0                                 # inbound edges once NAT nodes dial in
        for i in NAT:
            if t >= dial_t[i]:
                captured += 1
                line(draw, pos[i], pos[ATT], GREEN, 1)
            elif t >= dial_t[i] - TRAVEL:
                p = lerp(pos[i], pos[ATT], (t-(dial_t[i]-TRAVEL))/TRAVEL)
                circle(draw, p[0], p[1], 3, GREEN)

        for i in range(N):                           # the address gossiping along edges
            lf = learn_f[i]
            if lf >= 0 and learn_t[i]-TRAVEL < t < learn_t[i]:
                p = lerp(pos[lf], pos[i], 1-(learn_t[i]-t)/TRAVEL)
                circle(draw, p[0], p[1], 4, PURPLE)

        for i in LIS:
            circle(draw, pos[i][0], pos[i][1], 6, BLUE if t >= learn_t[i] else GREY)
        for i in NAT:
            knows = t >= learn_t[i]; dialed = t >= dial_t[i]
            col = GREEN if dialed else (PURPLE if knows else GREY)
            circle(draw, pos[i][0], pos[i][1], 5, col)
            if dialed:
                circle(draw, pos[i][0], pos[i][1], 8, None, GREEN)
        circle(draw, pos[ATT][0], pos[ATT][1], 12, ORANGE)
        text(draw, pos[ATT][0], pos[ATT][1] - 28, "LINKINGLION", ORANGE, size=22)
        legend(draw, LEG)

        known = sum(1 for i in range(1, N) if t >= learn_t[i])
        if known < N - 1 and captured == 0:
            text(draw, W//2, 42, "It relays its own address; peers gossip it onward", PURPLE, size=30)
            text(draw, W//2, H-36, f"nodes that now have its address: {known}/{N-1}", TEXT, size=27)
        elif captured < N_NAT:
            text(draw, W//2, 42, "Non-listening nodes learn it and dial in", GREEN, size=30)
            text(draw, W//2, H-36, f"NAT'd nodes captured: {captured}/{N_NAT}", TEXT, size=27)
        else:
            text(draw, W//2, 42, "Connected to nearly everyone, NAT'd nodes included", GREEN, size=30)
            text(draw, W//2, H-36,
                 f"captured {captured}/{N_NAT} non-listening nodes by advertising alone",
                 GREEN, size=27)

        frames.append(_finish_frame(img))

    for _ in range(FPS * 3):
        frames.append(frames[-1])
    save_gif(frames, os.path.join(FIGDIR, "nat_capture.gif"))


# ═══════════════════════════════════════════════════════════════
# 4a. TOPOLOGY — one tx, observer records first-announcer
# ═══════════════════════════════════════════════════════════════
SPOKE = (42, 35, 54)   # our (faint) connections to every node


def _net_layout():
    """Observer (LinkingLion) at the centre, connected to EVERY node; a ring of N
    network nodes with sparse hidden edges (the real topology we try to infer)."""
    cx, cy = W//2, H//2
    N = 9
    pos = []
    for i in range(N):
        a = TAU * i / N - TAU/4
        pos.append((cx + 255*math.cos(a), cy + 225*math.sin(a)))
    edges = [(i, (i+1) % N) for i in range(N)] + [(0, 2), (3, 5), (6, 8)]
    return (cx, cy), pos, edges, N


def _diffuse(src, pos, edges, mean):
    """Poisson-delay BFS. Returns (hear_time, hear_from)."""
    N = len(pos)
    ht = [float('inf')] * N; hf = [-1] * N; ht[src] = 0.0; q = [src]
    while q:
        cur = q.pop(0)
        for a, b in edges:
            peer = b if a == cur else (a if b == cur else -1)
            if peer < 0: continue
            arr = ht[cur] + poisson(mean)
            if arr < ht[peer]: ht[peer] = arr; hf[peer] = cur; q.append(peer)
    return ht, hf


def _draw_net(draw, obs, pos, edges, N, heard=None, src=None, owner=None,
              potential=(), spokes=True):
    """Shared scene: faint spokes to all, hidden edges, inferred links, nodes, us."""
    if spokes:
        for i in range(N):
            line(draw, obs, pos[i], SPOKE, 1)
    for a, b in edges:
        line(draw, pos[a], pos[b], FAINT, 2)
    for a, b in potential:                 # accumulated owner<->neighbour links
        line(draw, pos[a], pos[b], PURPLE, 4)
    for i in range(N):
        if i == owner:            col, r = GREEN, 13
        elif i == src:            col, r = ORANGE, 13
        elif heard and heard[i]:  col, r = BLUE, 11
        else:                     col, r = GREY, 11
        circle(draw, pos[i][0], pos[i][1], r, col)
    circle(draw, obs[0], obs[1], 15, RED)
    text(draw, obs[0], obs[1] + 32, "US — connected to all", RED, size=23)
    legend(draw, [(RED, "us (sees all)", "node"), (ORANGE, "source", "node"),
                  (YELLOW, "first announcer", "node"), (GREEN, "owner (rebroadcast)", "node"),
                  (PURPLE, "potential link", "line"), (GREY, "hidden edge", "line")])


def make_topology_step1():
    """One tx: first node to announce = potential neighbour; the later rebroadcast
    identifies the owner; the link between them is a potential topology edge —
    we learn a PATH exists, not whether it is a direct hop."""
    obs, pos, edges, N = _net_layout()
    SRC = 6
    ht, hf = _diffuse(SRC, pos, edges, 2.2)
    ann = [ht[i] + poisson(1.5) for i in range(N)]       # when each node announces to us
    first = min((i for i in range(N) if i != SRC), key=lambda i: ann[i])
    span = max(ann)
    frames = []

    for fi in range(FPS * 3):                            # Act 1a: setup
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 34, "We connect to every node and just listen", TEXT, size=30)
        _draw_net(draw, obs, pos, edges, N)
        text(draw, W//2, H-32, "a node near the source announces the new tx to us first", TEXT, size=26)
        frames.append(_finish_frame(img))

    nfr = int(6.0 * FPS)                                 # Act 1b: broadcast + mark neighbour
    for fi in range(nfr):
        dt = (fi / nfr) * (span + 0.8)
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 34, "A tx is broadcast — we watch who tells us first", BLUE, size=30)
        heard = [dt >= ht[i] for i in range(N)]
        _draw_net(draw, obs, pos, edges, N, heard, src=SRC)
        for i in range(N):                               # tx diffusing on hidden edges
            fr = hf[i]
            if fr >= 0 and ht[fr] < dt < ht[i]:
                p = lerp(pos[fr], pos[i], (dt-ht[fr])/(ht[i]-ht[fr]))
                circle(draw, p[0], p[1], 6, ORANGE)
        for i in range(N):                               # announcements travelling to us
            if ann[i] <= dt < ann[i] + 0.7:
                p = lerp(pos[i], obs, (dt-ann[i])/0.7)
                circle(draw, p[0], p[1], 5, YELLOW)
        if dt >= ann[first]:
            line(draw, pos[first], obs, YELLOW, 3)
            circle(draw, pos[first][0], pos[first][1], 15, None, YELLOW)
            text(draw, W//2, H-32, "first to tell us ≈ a neighbour of the source", YELLOW, size=26)
        else:
            text(draw, W//2, H-32, "announcements arriving…", TEXT, size=26)
        frames.append(_finish_frame(img))

    for fi in range(FPS * 4):                            # Act 2: rebroadcast reveals owner
        t = fi / FPS
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 34, "Later: only the owner rebroadcasts the unconfirmed tx", RED, size=30)
        _draw_net(draw, obs, pos, edges, N, heard=[True]*N, owner=SRC)
        circle(draw, pos[first][0], pos[first][1], 15, None, YELLOW)
        if (t % 2.0) < 1.2:                              # owner's lone announcement
            p = lerp(pos[SRC], obs, (t % 2.0)/1.2)
            circle(draw, p[0], p[1], 6, GREEN)
        text(draw, W//2, H-32, "the lone rebroadcast pins the owner", GREEN, size=26)
        frames.append(_finish_frame(img))

    for fi in range(FPS * 5):                            # Act 3: potential edge + caveat
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 34, "Owner  ↔  first-announcer  =  a potential link", PURPLE, size=30)
        _draw_net(draw, obs, pos, edges, N, heard=[True]*N, owner=SRC,
                  potential=[(min(SRC, first), max(SRC, first))])
        circle(draw, pos[first][0], pos[first][1], 15, None, YELLOW)
        text(draw, W//2, H-32, "we learn a path exists — not whether it's a direct hop", YELLOW, size=26)
        frames.append(_finish_frame(img))

    save_gif(frames, os.path.join(FIGDIR, "topology_step1.gif"))


def make_topology_step2():
    """Repeat over many txs from many sources: each owner<->neighbour link accretes
    into a probabilistic topology. We learn paths exist, not the exact direct edges."""
    obs, pos, edges, N = _net_layout()
    sources = [6, 2, 8, 4, 0, 7]
    potential = []
    frames = []

    for si, SRC in enumerate(sources):
        ht, hf = _diffuse(SRC, pos, edges, 2.2)
        ann = [ht[i] + poisson(1.5) for i in range(N)]
        first = min((i for i in range(N) if i != SRC), key=lambda i: ann[i])
        link = (min(SRC, first), max(SRC, first))
        span = max(ann)
        nfr = int(1.8 * FPS)
        for fi in range(nfr):
            dt = (fi / nfr) * (span + 0.6)
            img = _new_frame(); draw = ImageDraw.Draw(img)
            text(draw, W//2, 34,
                 f"Transaction {si+1} of {len(sources)}: mark neighbour, confirm owner",
                 TEXT, size=30)
            heard = [dt >= ht[i] for i in range(N)]
            _draw_net(draw, obs, pos, edges, N, heard, src=SRC, potential=potential)
            for i in range(N):
                fr = hf[i]
                if fr >= 0 and ht[fr] < dt < ht[i]:
                    p = lerp(pos[fr], pos[i], (dt-ht[fr])/(ht[i]-ht[fr]))
                    circle(draw, p[0], p[1], 5, ORANGE)
            if dt >= ann[first]:
                line(draw, pos[first], obs, YELLOW, 2)
                circle(draw, pos[first][0], pos[first][1], 14, None, YELLOW)
            if fi > nfr * 0.6:                           # rebroadcast confirms owner
                circle(draw, pos[SRC][0], pos[SRC][1], 14, None, GREEN)
            text(draw, W//2, H-32,
                 f"potential links so far: {len(potential)}", PURPLE, size=26)
            frames.append(_finish_frame(img))
        if link not in potential:
            potential.append(link)

    # a demonstrative link to question: the longest span reads clearest
    demo = max(potential, key=lambda e: dist(pos[e[0]], pos[e[1]])) if potential else None
    if demo:
        a, b = demo
        mx, my = lerp(pos[a], pos[b], 0.5)
        dx, dy = pos[b][0]-pos[a][0], pos[b][1]-pos[a][1]
        L = math.hypot(dx, dy) or 1
        gx, gy = mx - dy/L*48, my + dx/L*48            # ghost sits off the straight line

    for fi in range(FPS * 2):                            # C1: the probabilistic map
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 40, "Over time: a probabilistic topology", PURPLE, size=30)
        _draw_net(draw, obs, pos, edges, N, heard=[True]*N, potential=potential, spokes=False)
        text(draw, W//2, H-32,
             f"{len(potential)} owner-neighbour links accumulate", TEXT, size=26)
        frames.append(_finish_frame(img))

    for fi in range(FPS * 4):                            # C2: the honest open question
        t = fi / FPS
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 40, "Direct hop, or nodes in between?", YELLOW, size=30)
        _draw_net(draw, obs, pos, edges, N, heard=[True]*N, potential=potential, spokes=False)
        if demo:
            show_ghost = (t % 3.0) >= 1.5                # flicker between the two readings
            if show_ghost:                               # speculative detour via a ghost node
                line(draw, pos[a], (gx, gy), GREY, 2)
                line(draw, (gx, gy), pos[b], GREY, 2)
                pr = 11 + 2*math.sin(t*6)                # pulsing, outline-only = unsure
                circle(draw, gx, gy, int(pr), None, GREY)
                text(draw, gx, gy, "?", TEXT, size=26)
                text(draw, W//2, H-32, "maybe hidden nodes we never see", GREY, size=26)
            else:
                line(draw, pos[a], pos[b], YELLOW, 4)
                text(draw, W//2, H-32, "maybe a direct hop", YELLOW, size=26)
        frames.append(_finish_frame(img))

    save_gif(frames, os.path.join(FIGDIR, "topology_step2.gif"))


# ═══════════════════════════════════════════════════════════════
# 5. UTXO DEANON — fingerprint on-chain spends, filter to likely-Core
# ═══════════════════════════════════════════════════════════════
def _draw_tx(draw, x, y, color, filled=True, label=None, fade=False):
    """A transaction glyph: a rounded square tile with a ₿ mark. `color` tints
    the outline/mark; greyed tiles use GREY. Returns nothing."""
    s = 34
    fill = (22, 27, 35) if not fade else (16, 19, 25)
    draw.rounded_rectangle(
        [(x-s)*SS, (y-s)*SS, (x+s)*SS, (y+s)*SS],
        radius=8*SS, fill=fill, outline=color, width=2*SS)
    text(draw, x, y, "tx", color, size=24)
    if label:
        text(draw, x, y+s+16, label, color, size=16)


def make_utxo_deanon():
    """Fingerprinting candidate UTXOs (no spy / plant / rebroadcast here).

    A stream of on-chain spends is fingerprinted by wallet-construction
    heuristics (input ordering, change position, nVersion, anti-fee-sniping
    locktime). Only the spends that look like a Bitcoin Core wallet are kept;
    the rest are greyed out. Takeaway: probe a small filtered Core set, not
    the whole chain."""
    cx, cy = W//2, H//2

    # grid of on-chain spends (4 cols x 3 rows = 12 txs)
    cols, rows = 4, 3
    cw, ch = 150, 150
    gx0 = W//2 - (cols-1)*cw//2
    gy0 = 215
    cells = [(gx0 + c*cw, gy0 + r*ch) for r in range(rows) for c in range(cols)]
    NT = len(cells)

    # which spends look like a Core wallet (the ones we keep)
    IS_CORE = [False, True, False, True, False, False,
               True, False, True, False, False, False]
    core_idx = [i for i, v in enumerate(IS_CORE) if v]

    # a short rotating caption describing the heuristics being read
    HEURS = ["input ordering", "change position", "nVersion",
             "anti-fee-sniping locktime"]

    frames = []

    # --- 1: the mixed stream of on-chain spends ---
    for fi in range(FPS * 3):
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 48, "On-chain spends from many wallets", BLUE, size=30)
        for i, (x, y) in enumerate(cells):
            _draw_tx(draw, x, y, GREY)
        text(draw, W//2, H-44,
             "which of these were built by a Bitcoin Core wallet?", TEXT, size=26)
        frames.append(_finish_frame(img))

    # --- 2: read construction heuristics off each spend ---
    nb = FPS * 5
    for fi in range(nb):
        t = fi / nb
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 48, "Fingerprint by how each tx is built", ORANGE, size=30)
        # a scan sweeps across the grid; tiles it has passed get tagged
        scanned = int(t * (NT + 1))
        for i, (x, y) in enumerate(cells):
            if i < scanned:
                col = GREEN if IS_CORE[i] else GREY
                _draw_tx(draw, x, y, col)
                if IS_CORE[i]:
                    circle(draw, x, y, 46, None, GREEN)
            else:
                _draw_tx(draw, x, y, GREY)
        heur = HEURS[int(t * len(HEURS)) % len(HEURS)]
        text(draw, W//2, H-44,
             f"reading construction: {heur}", YELLOW, size=26)
        frames.append(_finish_frame(img))

    # hold on the fully-tagged grid
    for fi in range(FPS * 2):
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 48, "Fingerprint by how each tx is built", ORANGE, size=30)
        for i, (x, y) in enumerate(cells):
            col = GREEN if IS_CORE[i] else GREY
            _draw_tx(draw, x, y, col)
            if IS_CORE[i]:
                circle(draw, x, y, 46, None, GREEN)
        text(draw, W//2, H-44,
             f"{len(core_idx)} look like Bitcoin Core · the rest, other wallets",
             GREEN, size=26)
        frames.append(_finish_frame(img))

    # --- 3: drop the non-Core spends (grey tiles fade / vanish) ---
    nf = FPS * 3
    for fi in range(nf):
        t = fi / nf
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 48, "Keep only the likely-Core spends", GREEN, size=30)
        for i, (x, y) in enumerate(cells):
            if IS_CORE[i]:
                _draw_tx(draw, x, y, GREEN)
                circle(draw, x, y, 46, None, GREEN)
            elif t < 0.85:
                _draw_tx(draw, x, y, GREY, fade=True)
        text(draw, W//2, H-44,
             "drop everything that isn't a Core wallet", TEXT, size=26)
        frames.append(_finish_frame(img))

    # --- 4: the filtered candidate set ---
    for fi in range(FPS * 5):
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 48, "The candidate set to probe", GREEN, size=30)
        # re-center the surviving Core txs in a tidy row
        n = len(core_idx)
        row_y = cy - 10
        row_x0 = W//2 - (n-1)*cw//2
        for k in range(n):
            x = row_x0 + k*cw
            _draw_tx(draw, x, row_y, GREEN)
            circle(draw, x, row_y, 46, None, GREEN)
        text(draw, W//2, cy + 120,
             f"{NT} spends  →  {n} likely-Core candidates", GREEN, size=28)
        text(draw, W//2, H-44,
             "probe this filtered set, not every address on the chain",
             YELLOW, size=26)
        frames.append(_finish_frame(img))

    for _ in range(FPS * 2):
        frames.append(frames[-1])
    save_gif(frames, os.path.join(FIGDIR, "utxo_deanon.gif"))


# ═══════════════════════════════════════════════════════════════
# 6. CLUSTERING — many pinned UTXOs → an address-to-node map
# ═══════════════════════════════════════════════════════════════
def make_clustering():
    """Repeat the pin across many UTXOs: each candidate UTXO gets pinned to a
    node IP, and they accrete into an address→node map. Addresses grouped under
    the same node form a cluster.  CAVEAT: a cluster is an address-to-NODE
    association, NOT proof of common ownership."""
    cx, cy = W//2, H//2

    # node IPs on the right; addresses pinned on the left as they accrete
    NODES = 3
    node_pos = [(W - 260, cy - 150 + i*150) for i in range(NODES)]
    node_names = ["node A", "node B", "node C"]

    # a stream of candidate UTXOs → which node each pins to (some share nodes)
    pins = [0, 1, 0, 2, 0, 1, 2, 0]      # node index each UTXO pins to
    # left-hand slot for each address as it lands near its node
    def addr_slot(node_i, k):
        base = node_pos[node_i]
        return (base[0] - 230, base[1] - 45 + k*34)

    ADDR_SRC = (200, cy)                 # where a fresh candidate UTXO appears

    CL_LEG = [(ORANGE, "candidate address", "node"), (BLUE, "node IP", "node"),
              (RED, "lone rebroadcast", "line"), (PURPLE, "address→node link", "line")]

    def draw_nodes(draw, active=None):
        for i, (x, y) in enumerate(node_pos):
            col = GREEN if i == active else BLUE
            circle(draw, x, y, 14, col)
            circle(draw, x, y, 14, None, GREEN if i == active else None)
            text(draw, x, y+26, node_names[i], col, size=19)

    def draw_pinned(draw, placed):
        """placed: list of (node_i, slot_k) already pinned."""
        counts = {}
        for node_i, _ in placed:
            counts[node_i] = counts.get(node_i, 0)
        for idx, (node_i, k) in enumerate(placed):
            ax, ay = addr_slot(node_i, k)
            circle(draw, ax, ay, 11, None, ORANGE)
            circle(draw, ax, ay, 4, ORANGE)
            line(draw, (ax+12, ay), (node_pos[node_i][0]-16, node_pos[node_i][1]), PURPLE, 2)

    frames = []
    placed = []
    slot_count = [0]*NODES

    # --- Act 1: pin candidate UTXOs one by one ---
    for pi, node_i in enumerate(pins):
        k = slot_count[node_i]
        # a1: candidate appears + dust planted (compressed)
        for fi in range(FPS * 1):
            t = fi / FPS
            img = _new_frame(); draw = ImageDraw.Draw(img)
            text(draw, W//2, 44, f"Pin UTXO {pi+1} of {len(pins)}: plant dust", TEXT, size=30)
            legend(draw, CL_LEG)
            draw_nodes(draw)
            draw_pinned(draw, placed)
            circle(draw, ADDR_SRC[0], ADDR_SRC[1], 16, None, ORANGE)
            circle(draw, ADDR_SRC[0], ADDR_SRC[1], 5, ORANGE)
            text(draw, ADDR_SRC[0], ADDR_SRC[1]+28, "candidate address", ORANGE, size=18)
            text(draw, W//2, H-34, "plant dust to the candidate address", TEXT, size=26)
            frames.append(_finish_frame(img))
        # a2: the target node rebroadcasts -> pin travels and lands
        for fi in range(FPS * 2):
            t = fi / FPS
            img = _new_frame(); draw = ImageDraw.Draw(img)
            text(draw, W//2, 44, f"Pin UTXO {pi+1} of {len(pins)}: rebroadcast → node IP", RED, size=30)
            legend(draw, CL_LEG)
            draw_nodes(draw, active=node_i)
            draw_pinned(draw, placed)
            # rebroadcast line from node to spy's view, then address flies to its slot
            prog = min(1, t / 1.8)
            tgt = addr_slot(node_i, k)
            p = lerp(ADDR_SRC, tgt, prog)
            circle(draw, p[0], p[1], 11, None, ORANGE)
            circle(draw, p[0], p[1], 4, ORANGE)
            if prog > 0.4:
                # a lone rebroadcast pulse from the node
                pr = min(1, (t-0.7)/1.0)
                lp = lerp(node_pos[node_i], tgt, pr)
                circle(draw, lp[0], lp[1], 5, RED)
            text(draw, W//2, H-34, "rebroadcast pins this address to a node IP", YELLOW, size=26)
            frames.append(_finish_frame(img))
        placed.append((node_i, k))
        slot_count[node_i] += 1

    # --- Act 2: the accreted map, clusters emerge ---
    for fi in range(FPS * 3):
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 44, "The pins accrete into an address → node map", PURPLE, size=30)
        legend(draw, CL_LEG)
        draw_nodes(draw)
        draw_pinned(draw, placed)
        # outline clusters: nodes with >1 address grouped
        for i in range(NODES):
            n = slot_count[i]
            if n > 1:
                bx = node_pos[i][0] - 230
                by = node_pos[i][1] - 45
                x0, y0 = bx - 24, by - 24
                x1, y1 = node_pos[i][0] + 40, by + (n-1)*34 + 24
                draw.rectangle([x0*SS, y0*SS, x1*SS, y1*SS], outline=GREEN, width=2*SS)
                text(draw, (x0+x1)//2, y0-14, f"cluster · {n} addresses", GREEN, size=18)
        text(draw, W//2, H-34, "many addresses under one node IP = a cluster", GREEN, size=26)
        frames.append(_finish_frame(img))

    # --- Act 3: accuracy caveat ---
    for fi in range(FPS * 4):
        img = _new_frame(); draw = ImageDraw.Draw(img)
        text(draw, W//2, 44, "What a cluster is — and is not", YELLOW, size=30)
        legend(draw, CL_LEG)
        draw_nodes(draw)
        draw_pinned(draw, placed)
        for i in range(NODES):
            n = slot_count[i]
            if n > 1:
                bx = node_pos[i][0] - 230
                by = node_pos[i][1] - 45
                x0, y0 = bx - 24, by - 24
                x1, y1 = node_pos[i][0] + 40, by + (n-1)*34 + 24
                draw.rectangle([x0*SS, y0*SS, x1*SS, y1*SS], outline=GREEN, width=2*SS)
        text(draw, W//2, H-34, "same-node ≠ same owner — association, not proof", YELLOW, size=26)
        frames.append(_finish_frame(img))

    for _ in range(FPS * 2):
        frames.append(frames[-1])
    save_gif(frames, os.path.join(FIGDIR, "clustering.gif"))


# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("generating animated GIFs…")
    make_diffusion()
    make_rebroadcast()
    make_nat_capture()
    make_topology_step1()
    make_topology_step2()
    make_utxo_deanon()
    make_clustering()
    print("done.")
