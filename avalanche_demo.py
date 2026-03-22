#!/usr/bin/env python3
"""
avalanche_demo.py — Bit Diffusion Analysis for the Secure GFN Block Cipher
===========================================================================
Shows how a single flipped bit in the plaintext or key propagates through
all 32 Feistel rounds, converging toward the ideal 50 % Hamming distance.

Run:  python avalanche_demo.py
      python avalanche_demo.py --trials 50   (more samples for statistics)

With MixBytes (GF(2^8), branch number 5), full avalanche (>45 %) is
typically reached by round 6–8, well ahead of the 32-round full schedule.
"""

import os
import sys
import argparse

# Force UTF-8 stdout to avoid UnicodeEncodeError on Windows terminals with non-UTF-8 locales
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from cipher import derive_keys, derive_subkeys, round_function, xor_bytes


# ─────────────────────────────────────────────────────────────────────────────
#  Core analysis
# ─────────────────────────────────────────────────────────────────────────────
def hamming(b1: bytes, b2: bytes) -> int:
    return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))


def get_round_states(block: bytes, subkeys: list) -> list:
    """Return 33 snapshots (rounds 0–32) of the full 512-byte GFN state."""
    X = [block[i * 128:(i + 1) * 128] for i in range(4)]
    states = [b"".join(X)]
    for r in range(32):
        k0, k1 = subkeys[2 * r], subkeys[2 * r + 1]
        f0 = round_function(X[1], k0)
        f1 = round_function(X[3], k1)
        y0 = xor_bytes(X[0], f0)
        y2 = xor_bytes(X[2], f1)
        X = [X[1], y2, X[3], y0]
        states.append(b"".join(X))
    return states


def run_analysis(trials: int = 20, password: str = "AvalancheDemo2025"):
    salt    = os.urandom(16)
    k_enc, _ = derive_keys(password, salt)
    subkeys  = derive_subkeys(k_enc)

    pt_by_round  = [[] for _ in range(33)]
    key_by_round = [[] for _ in range(33)]

    for _ in range(trials):
        blk     = os.urandom(512)
        mut_pt  = bytes([blk[0] ^ 0x01]) + blk[1:]
        k_mut   = bytes([k_enc[0] ^ 0x01]) + k_enc[1:]
        sk_mut  = derive_subkeys(k_mut)

        s_orig  = get_round_states(blk,    subkeys)
        s_pt    = get_round_states(mut_pt, subkeys)
        s_key   = get_round_states(blk,    sk_mut)

        for r in range(33):
            pt_by_round[r].append(hamming(s_orig[r], s_pt[r]))
            key_by_round[r].append(hamming(s_orig[r], s_key[r]))

    pt_avg  = [sum(v) / trials for v in pt_by_round]
    key_avg = [sum(v) / trials for v in key_by_round]
    return pt_avg, key_avg


# ─────────────────────────────────────────────────────────────────────────────
#  Display helpers
# ─────────────────────────────────────────────────────────────────────────────
WIDTH  = 50   # bar chart width
MAX    = 4096
IDEAL  = MAX // 2

def _bar(val: float) -> str:
    filled = int(round(val / MAX * WIDTH))
    empty  = WIDTH - filled
    return "█" * filled + "░" * empty

def _row(r: int, pt: float, key: float) -> str:
    return (f"  {r:02d} │ {_bar(pt)} {pt:5.0f} ({pt/MAX*100:4.1f}%)"
            f" │ {key:5.0f} ({key/MAX*100:4.1f}%)")

def print_report(pt_avg: list, key_avg: list, trials: int) -> None:
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN= "\033[92m"
    YEL  = "\033[93m"
    RST  = "\033[0m"

    print()
    print(BOLD + CYAN + "═" * 80 + RST)
    print(BOLD + CYAN + "  AVALANCHE EFFECT  —  Secure GFN v2 with MixBytes  "
          + f"(n={trials} trials, block=4096-bit)" + RST)
    print(BOLD + CYAN + "═" * 80 + RST)

    print(f"\n  {'Round':>5} │ {'1-bit Plaintext Change':^{WIDTH+16}} │ {'1-bit Key Change':>16}")
    print("  " + "─" * 5 + "┼" + "─" * (WIDTH + 17) + "┼" + "─" * 18)

    first_pt_full = first_key_full = None
    for r in range(33):
        line = _row(r, pt_avg[r], key_avg[r])
        if pt_avg[r] / MAX >= 0.45 and first_pt_full is None:
            first_pt_full = r
        if key_avg[r] / MAX >= 0.45 and first_key_full is None:
            first_key_full = r
        if r in {0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 20, 24, 28, 32}:
            print(line)

    print("\n" + "─" * 80)

    # Summary table
    print(f"\n  {'Metric':<45} {'Plaintext':>12} {'Key':>12}")
    print("  " + "─" * 70)
    rows = [
        ("Bits changed at round 0  (before any rounds)", pt_avg[0], key_avg[0]),
        ("Bits changed at round 4", pt_avg[4], key_avg[4]),
        ("Bits changed at round 8", pt_avg[8], key_avg[8]),
        ("Bits changed at round 16", pt_avg[16], key_avg[16]),
        ("Bits changed at round 32 (final)", pt_avg[32], key_avg[32]),
        ("Final percentage of 4096 bits", pt_avg[32]/MAX*100, key_avg[32]/MAX*100),
        ("Deviation from ideal 50%", abs(pt_avg[32]/MAX - 0.5)*100, abs(key_avg[32]/MAX - 0.5)*100),
    ]
    for label, pt_v, key_v in rows:
        if "percentage" in label or "Deviation" in label:
            print(f"  {label:<45} {pt_v:>11.3f}% {key_v:>11.3f}%")
        else:
            print(f"  {label:<45} {pt_v:>11.0f}  {key_v:>11.0f}")

    print()
    print(GREEN + f"  ✓ Plaintext: full avalanche (≥45%) first reached at round {first_pt_full}" + RST)
    print(GREEN + f"  ✓ Key:       full avalanche (≥45%) first reached at round {first_key_full}" + RST)

    print()
    print(YEL + "  Round function pipeline (each round F applies 4 stages):" + RST)
    print("     Stage 1 │ XOR with 1024-bit round subkey              (key whitening)")
    print("     Stage 2 │ AES S-Box substitution byte-by-byte         (non-linear confusion)")
    print("     Stage 3 │ 1024-bit deterministic bit permutation       (local diffusion)")
    print("     Stage 4 │ MixBytes — GF(2^8) MixColumns, branch #5   (global diffusion) ← NEW")
    print()
    print("  MixBytes ensures any 1-byte difference at Stage 2 output spreads to")
    print("  4 bytes before the next round, halving the rounds needed for full avalanche.")
    print()

    # Try matplotlib
    try:
        import matplotlib
        matplotlib.use("TkAgg")
        import matplotlib.pyplot as plt

        rounds = list(range(33))
        fig, ax = plt.subplots(figsize=(11, 5))
        fig.patch.set_facecolor("#0f0f1a")
        ax.set_facecolor("#16162a")

        ax.plot(rounds, [v / MAX * 100 for v in pt_avg],
                color="#7c5cbf", lw=2.5, marker="o", ms=4, label="1-bit Plaintext Change")
        ax.plot(rounds, [v / MAX * 100 for v in key_avg],
                color="#e05c6e", lw=2.5, marker="x", ms=5, label="1-bit Key Change")
        ax.axhline(50, color="#f0c060", lw=1.5, ls="--", label="Ideal 50%")
        ax.axhline(45, color="#4ec98e", lw=1.0, ls=":", alpha=0.7, label="45% Threshold")

        if first_pt_full:
            ax.axvline(first_pt_full, color="#7c5cbf", lw=1.0, ls=":", alpha=0.6)
        if first_key_full:
            ax.axvline(first_key_full, color="#e05c6e", lw=1.0, ls=":", alpha=0.6)

        ax.set_xlabel("Feistel Round", color="#9090b8")
        ax.set_ylabel("Hamming Distance (% of 4096 bits)", color="#9090b8")
        ax.set_title("Avalanche Effect — Secure GFN v2 with MixBytes",
                     color="#a87fd4", fontsize=13, fontweight="bold")
        ax.tick_params(colors="#9090b8")
        for spine in ax.spines.values():
            spine.set_edgecolor("#2a2a45")
        ax.grid(True, color="#2a2a45", linewidth=0.8)
        ax.set_xlim(0, 32)
        ax.set_ylim(0, 65)
        ax.legend(facecolor="#1e1e35", edgecolor="#2a2a45", labelcolor="#e0e0f0")

        plt.tight_layout()
        plt.show()
    except Exception:
        print("  (Install matplotlib for a graphical plot: pip install matplotlib)")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Avalanche Effect Analysis for the Secure GFN Block Cipher")
    parser.add_argument("--trials", type=int, default=20,
                        help="Number of random block trials to average (default: 20)")
    args = parser.parse_args()

    print(f"  Running avalanche analysis over {args.trials} random block trials…")
    pt_avg, key_avg = run_analysis(trials=args.trials)
    print_report(pt_avg, key_avg, trials=args.trials)
