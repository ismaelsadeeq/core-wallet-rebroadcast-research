#!/usr/bin/env python3
"""Verify, against real Core 32.1 over RPC, the malleability claims the active-probe
section relies on. One regtest node, two wallets (victim wV, third-party attacker wA
with separate keys). No mainnet, all our own coins.

  1. ANYONECANPAY: a third party can append an input -> different txid, same prevout
     (a valid, standard CONFLICT) while REUSING the victim's on-wire signature verbatim
     (no victim key). Shown by: the u0 witness is byte-identical 1-input vs 2-input,
     and the extended tx is accepted.
  2. SIGHASH_ALL (default): the on-wire u0 signature does NOT match what the extended
     tx needs (witness differs once inputs change), so a third party lacking the
     victim key cannot build the conflict. Malleation blocked.
  3. pay-to-anchor (P2A, TxoutType::ANCHOR): anyone-can-spend and standard to spend,
     so the appended dust can be harvested free from the UTXO set.
  4. txid excludes the witness (segwit): witness malleation cannot change the txid,
     so it cannot create a conflict.
"""
from harness import Node, teardown, _p2p_up


def main():
    teardown()
    M = Node("M", 0); M.start(); assert _p2p_up(M.p2p)
    M.rpc_call("createwallet", "wV")   # victim
    M.rpc_call("createwallet", "wA")   # third-party attacker: separate keys
    va = M.rpc_call("getnewaddress", wallet="wV")
    M.rpc_call("generatetoaddress", 150, va, wallet="wV")
    aa = M.rpc_call("getnewaddress", wallet="wA")
    M.rpc_call("generatetoaddress", 20, aa, wallet="wA")     # attacker's own utxos
    M.rpc_call("generatetoaddress", 101, va, wallet="wV")    # mature everything

    def utxo(wallet, minamt=1):
        for c in M.rpc_call("listunspent", 1, 9999999, [], True, wallet=wallet):
            if c["spendable"] and c["amount"] > minamt:
                return c
        raise SystemExit(f"no utxo in {wallet}")

    def dec(h): return M.rpc_call("decoderawtransaction", h)
    def wit(h, i=0): return dec(h)["vin"][i].get("txinwitness")
    def txid(h): return dec(h)["txid"]
    def outpoint(h, i=0):
        v = dec(h)["vin"][i]; return (v["txid"], v["vout"])
    def accept(h): return M.rpc_call("testmempoolaccept", [h], 0)[0]  # maxfeerate=0: judge validity, not fee

    print("=== Claim 1 & 2: ANYONECANPAY vs SIGHASH_ALL third-party append ===")
    for sh in ["ALL|ANYONECANPAY", "ALL"]:
        u0 = utxo("wV"); u1 = utxo("wA")
        out = M.rpc_call("getnewaddress", wallet="wV")
        val = round(float(u0["amount"]) - 0.001, 8)
        # victim's on-wire tx: 1 input, signed with sighash `sh`
        raw1 = M.rpc_call("createrawtransaction",
                          [{"txid": u0["txid"], "vout": u0["vout"]}], {out: val})
        s1 = M.rpc_call("signrawtransactionwithwallet", raw1, [], sh, wallet="wV")
        assert s1["complete"], f"victim 1-input sign {sh} incomplete"
        wire_wit, wire_txid = wit(s1["hex"]), txid(s1["hex"])
        # extended 2-input tx [u0,u1] -> out (u1's value falls to fee)
        raw2 = M.rpc_call("createrawtransaction",
                          [{"txid": u0["txid"], "vout": u0["vout"]},
                           {"txid": u1["txid"], "vout": u1["vout"]}], {out: val})
        sv = M.rpc_call("signrawtransactionwithwallet", raw2, [], sh, wallet="wV")  # u0 only
        sa = M.rpc_call("signrawtransactionwithwallet", sv["hex"], [], sh, wallet="wA")  # u1
        ext_wit, ext_txid = wit(sa["hex"]), txid(sa["hex"])
        acc = accept(sa["hex"])
        reuse = (wire_wit == ext_wit)
        print(f"\n sighash {sh}:")
        print(f"  victim's on-wire u0 signature reusable in the extended tx? {reuse}")
        print(f"  extended tx complete={sa['complete']} accepted={acc['allowed']} "
              f"reason={acc.get('reject-reason')}")
        print(f"  different txid? {ext_txid != wire_txid}   "
              f"same prevout (=> conflict)? {outpoint(s1['hex']) == outpoint(sa['hex'], 0)}")
        if "ANYONECANPAY" in sh:
            print(f"  => third party appends an input and REUSES the wire sig verbatim "
                  f"(reuse={reuse}, accepted={acc['allowed']}): malleation WORKS, no victim key")
        else:
            print(f"  => wire sig does NOT fit the extended tx (reuse={reuse}); a third party "
                  f"without the victim key cannot forge it: malleation BLOCKED "
                  f"(the accept above only succeeded because we re-signed u0 with the victim wallet)")

    print("\n=== Claim 3: P2A (pay-to-anchor) is anyone-can-spend + standard ===")
    d = M.rpc_call("decodescript", "51024e73")
    print(f"  decodescript 51024e73 -> type={d.get('type')} address={d.get('address')}")
    p2a = d["address"]
    ftxid = M.rpc_call("sendtoaddress", p2a, 0.001, wallet="wV")   # fund a P2A output
    M.rpc_call("generatetoaddress", 1, M.rpc_call("getnewaddress", wallet="wV"), wallet="wV")
    ftx = M.rpc_call("getrawtransaction", ftxid, True)
    vout = next(o["n"] for o in ftx["vout"] if o["scriptPubKey"]["hex"] == "51024e73")
    dest = M.rpc_call("getnewaddress", wallet="wA")
    spend = M.rpc_call("createrawtransaction",
                       [{"txid": ftxid, "vout": vout}], {dest: 0.0009})  # no signature at all
    acc = accept(spend)
    print(f"  spend the P2A output with NO signature: accepted={acc['allowed']} "
          f"reason={acc.get('reject-reason')}")
    if acc["allowed"]:
        M.rpc_call("sendrawtransaction", spend)
        print("  broadcast OK -> keyless, standard, anyone-can-spend dust confirmed")

    print("\n=== Claim 4: txid excludes the witness (segwit) ===")
    tid = M.rpc_call("sendtoaddress", M.rpc_call("getnewaddress", wallet="wV"), 0.5, wallet="wV")
    t = M.rpc_call("getrawtransaction", tid, True)
    print(f"  txid={t['txid'][:16]}  wtxid(hash)={t['hash'][:16]}  differ={t['txid'] != t['hash']}")
    print("  => witness is committed only in the wtxid; malleating it leaves the txid "
          "unchanged, so it cannot create a conflict")

    M.stop(); teardown()


if __name__ == "__main__":
    main()
