#!/usr/bin/env python3
"""
Validate the cost table for the dust-payment deanonymization attack-cost calc.

Scenario: one input + one output tx, planted dust payment that must RELAY
(pay >= min relay fee) but not necessarily confirm, carrying a dust-value output
(below the dust threshold so it is an identifiable marker).

All fee/dust figures are in satoshis unless noted.
"""

from math import ceil

# ---- Constants ----
DEFAULT_MIN_RELAY_TX_FEE = 100   # sat / kvB  -> 0.1 sat/vB
MIN_RELAY_SAT_PER_VB = DEFAULT_MIN_RELAY_TX_FEE / 1000.0  # 0.1 sat/vB

K = 5  # targets per round

# price assumption to CHECK: 1 sat = $0.00059  (=> $59,000 / BTC)
USD_PER_SAT = 0.00059

# Per output type: (dust threshold sat @ 3000 sat/kvB, tx size vB)
TYPES = {
    "P2WPKH": {"dust": 294, "vB": 110},
    "P2TR":   {"dust": 330, "vB": 111},
    "P2PKH":  {"dust": 546, "vB": 192},
}


def compute(vB, dust):
    fee_exact = vB * MIN_RELAY_SAT_PER_VB          # exact sat (may be fractional)
    fee = ceil(fee_exact)                          # integer sat actually paid
    per_tx = fee + dust                            # sat
    round_cost = per_tx * K                        # sat
    round_usd = round_cost * USD_PER_SAT
    per_target_usd = per_tx * USD_PER_SAT
    return fee_exact, fee, per_tx, round_cost, round_usd, per_target_usd


def main():
    print(f"Assumptions: min relay = {MIN_RELAY_SAT_PER_VB} sat/vB, "
          f"K = {K} targets/round, 1 sat = ${USD_PER_SAT} "
          f"(=> ${USD_PER_SAT*1e8:,.0f}/BTC)\n")

    header = (f"{'Type':<7} {'vB':>4} {'dust':>5} {'fee_exact':>10} "
              f"{'fee':>4} {'per_tx':>7} {'round_sat':>10} "
              f"{'round_USD':>10} {'per_tgt_USD':>12}")
    print(header)
    print("-" * len(header))

    for name, p in TYPES.items():
        fe, fee, per_tx, rc, rusd, ptusd = compute(p["vB"], p["dust"])
        print(f"{name:<7} {p['vB']:>4} {p['dust']:>5} {fe:>10.1f} "
              f"{fee:>4} {per_tx:>7} {rc:>10} "
              f"${rusd:>9.4f} ${ptusd:>11.4f}")

    print()

    # ---- Sanity check: the "about a tenth of a cent" claim ----
    # Draft reference figure: 1,525 sat per round (P2TR-ish example).
    draft_round_sat = 1525
    claimed_usd = 0.001          # "a tenth of a cent" = $0.001
    actual_usd = draft_round_sat * USD_PER_SAT
    factor = actual_usd / claimed_usd

    print("Sanity-check of 'about a tenth of a cent' per round:")
    print(f"  draft round reference = {draft_round_sat} sat")
    print(f"  claimed  = ${claimed_usd:.4f} (a tenth of a cent)")
    print(f"  actual   = {draft_round_sat} x ${USD_PER_SAT} = ${actual_usd:.4f}")
    print(f"  VERDICT  = claim is OFF by {factor:.0f}x "
          f"(actual is ~${actual_usd:.2f}, i.e. ~90 cents, not a tenth of a cent).")


if __name__ == "__main__":
    main()
