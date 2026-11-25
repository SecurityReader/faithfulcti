#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Recompute inter-annotator agreement (Cohen's kappa) from the released
105-case dual-label table (iaa/iaa_105_dual_labels.csv).

Reports quadratic-weighted kappa for ordinal labels (reasoning_tier, gt_match)
and unweighted Cohen's kappa for nominal labels. Reported kappa in the paper is
PRE-adjudication (i.e., from these two independent annotators).

Usage:  python compute_kappa.py        # reads ./iaa_105_dual_labels.csv
Dependency: standard library only.
"""
import csv, os

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "iaa_105_dual_labels.csv")

def cohen_kappa(pairs, order=None, weighted=False):
    pairs = [(a, b) for a, b in pairs if a not in (None, "") and b not in (None, "")]
    n = len(pairs)
    if n == 0:
        return None, 0
    cats = sorted(set([a for a, _ in pairs] + [b for _, b in pairs]),
                  key=lambda x: order.index(x) if order and x in order else 99)
    idx = {c: i for i, c in enumerate(cats)}
    K = len(cats)
    O = [[0] * K for _ in range(K)]
    for a, b in pairs:
        O[idx[a]][idx[b]] += 1
    ra = [sum(O[i]) for i in range(K)]
    cb = [sum(O[i][j] for i in range(K)) for j in range(K)]
    def w(i, j):
        if not weighted:
            return 0 if i == j else 1
        m = K - 1
        return ((i - j) / m) ** 2 if m else 0
    num = sum(w(i, j) * O[i][j] for i in range(K) for j in range(K))
    den = sum(w(i, j) * ra[i] * cb[j] / n for i in range(K) for j in range(K))
    if den == 0:
        return 1.0, n
    return 1 - num / den, n

def interp(k):
    if k is None: return "-"
    if k < 0.2: return "slight"
    if k < 0.4: return "fair"
    if k < 0.6: return "moderate"
    if k < 0.8: return "substantial"
    return "almost perfect"

def main():
    rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
    specs = [
        ("reasoning_tier", ["T1", "T2", "T3", "T4"], True),
        ("gt_match", ["N", "partial", "Y"], True),
        ("unfaithful_type", None, False),
        ("gt_quality", None, False),
        ("cue_mention", None, False),
    ]
    print(f"IAA on {len(rows)} dual-labeled cases (A1 vs A2)")
    print(f"{'label':<18}{'kappa':>8}  {'interp':<16}{'agree':>7}  n")
    print("-" * 60)
    for key, order, wt in specs:
        pairs = [(r["A1_" + key], r["A2_" + key]) for r in rows]
        k, n = cohen_kappa(pairs, order=order, weighted=wt)
        valid = [(a, b) for a, b in pairs if a not in (None, "") and b not in (None, "")]
        agree = sum(1 for a, b in valid if a == b) / len(valid) if valid else 0
        tag = "weighted" if wt else "Cohen"
        kv = f"{k:.3f}" if k is not None else "-"
        print(f"{key:<18}{kv:>8}  {interp(k):<16}{agree*100:5.1f}%  {n}  [{tag}]")

if __name__ == "__main__":
    main()
