#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regenerate the four result figures from released artifacts.
Inputs (repo-relative):  labels/gold_labels.xlsx, traces/scored/*_scored_v4f.jsonl
Output: figures/fig1..fig4.png
Run from the repository root:  python scripts/make_figures.py
Dependencies: openpyxl, numpy, matplotlib, scipy
"""
import os, json
import numpy as np
import openpyxl
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import chi2_contingency

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLD = os.path.join(ROOT, "labels", "gold_labels.xlsx")
SCORED = os.path.join(ROOT, "traces", "scored")
OUT = os.path.join(ROOT, "figures")
plt.rcParams.update({"font.family": "DejaVu Sans", "axes.unicode_minus": False, "savefig.dpi": 300})

ws = openpyxl.load_workbook(GOLD)["라벨링"]
H = [(ws.cell(1, c).value or "") for c in range(1, ws.max_column + 1)]
def col(s):
    for i, h in enumerate(H):
        if s in h: return i + 1
MI, GM, RT, UT = col("model"), col("gt_match"), col("reasoning_tier"), col("unfaithful_type")
rows = [dict(m=ws.cell(r, MI).value, gm=ws.cell(r, GM).value, rt=ws.cell(r, RT).value, ut=ws.cell(r, UT).value)
        for r in range(2, ws.max_row + 1)]
models = ["GPT-5.6 Sol", "Haiku 4.5", "Qwen 397B"]
mlabel = ["GPT-5.6 Sol\n(frontier)", "Haiku 4.5\n(weak)", "Qwen 397B\n(open)"]
C = {"GPT-5.6 Sol": "#2E5EAA", "Haiku 4.5": "#C0504D", "Qwen 397B": "#7B5EA7"}
cols = [C[m] for m in models]
mf = {"GPT-5.6 Sol": "gpt56sol", "Haiku 4.5": "haiku45", "Qwen 397B": "qwen397b"}
def load(f): return [json.loads(l) for l in open(f) if l.strip()]

# Fig1: accuracy by task band (machine)
bands = ["knowledge MCQ", "CVSS severity reasoning", "CVE→CWE mapping", "ATT&CK technique extraction"]
blab = ["Knowledge\nMCQ", "CVSS\nseverity", "CVE→CWE", "ATT&CK"]
fig, ax = plt.subplots(figsize=(7.5, 4.2)); x = np.arange(len(bands)); w = 0.25
for k, m in enumerate(models):
    R = load(os.path.join(SCORED, f"{mf[m]}_main_200_scored_v4f.jsonl")); vals = []
    for b in bands:
        sub = [r for r in R if r["task_type"] == b]
        vals.append(100 * sum(r["gt_hit"] is True for r in sub) / len(sub) if sub else 0)
    ax.bar(x + (k - 1) * w, vals, w, label=m, color=C[m], edgecolor="black", lw=0.5)
ax.set_xticks(x); ax.set_xticklabels(blab); ax.set_ylabel("Accuracy (%)"); ax.set_ylim(0, 100)
ax.set_title("Accuracy by task band (machine, v4f)", fontweight="bold"); ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)
plt.tight_layout(); plt.savefig(os.path.join(OUT, "fig1_accuracy_by_band.png")); plt.close()

# Fig2: unfaithful-yet-correct (Y & T2/T1)
rates = []; labels = []; tab = []
for m in models:
    Y = [r for r in rows if r["m"] == m and r["gm"] == "Y"]; bad = sum(1 for r in Y if r["rt"] in ("T2", "T1"))
    rates.append(100 * bad / len(Y)); labels.append(f"{bad}/{len(Y)}"); tab.append((bad, len(Y) - bad))
chi, p, _, _ = chi2_contingency(np.array(tab))
fig, ax = plt.subplots(figsize=(6, 4.2)); ax.bar(mlabel, rates, color=cols, width=0.6, edgecolor="black", lw=0.6)
for i, (rt, lb) in enumerate(zip(rates, labels)):
    ax.text(i, rt + 0.3, f"{rt:.1f}%\n({lb})", ha="center", va="bottom", fontsize=10, fontweight="bold")
ax.set_ylabel("Unfaithful-yet-correct rate (%)\n[T2/T1 among correct]")
ax.set_title(f"Right answer, flawed reasoning (Y & T2/T1)\nχ²={chi:.2f}, p={p:.4f}", fontweight="bold")
ax.set_ylim(0, 17); ax.grid(axis="y", alpha=0.3); plt.tight_layout(); plt.savefig(os.path.join(OUT, "fig2_unfaithful_correct.png")); plt.close()

# Fig3: accuracy x faithfulness cross-tab
fig, axes = plt.subplots(1, 3, figsize=(13, 3.6)); tiers = ["T4", "T3", "T2", "T1"]; gms = ["Y", "partial", "N"]
for ax, m in zip(axes, models):
    sub = [r for r in rows if r["m"] == m]
    M = np.array([[sum(1 for r in sub if r["gm"] == g and r["rt"] == t) for t in tiers] for g in gms])
    ax.imshow(M, cmap="YlOrRd", aspect="auto")
    ax.set_xticks(range(4)); ax.set_xticklabels(tiers); ax.set_yticks(range(3)); ax.set_yticklabels(gms)
    for i in range(3):
        for j in range(4):
            ax.text(j, i, M[i, j], ha="center", va="center", fontsize=10,
                    color="white" if M[i, j] > M.max() * 0.5 else "black", fontweight="bold")
    ax.set_title(m, fontweight="bold"); ax.set_xlabel("reasoning tier")
axes[0].set_ylabel("gt_match"); fig.suptitle("Accuracy × Faithfulness cross-tabulation", fontweight="bold", y=1.02)
plt.tight_layout(); plt.savefig(os.path.join(OUT, "fig3_crosstab_heatmap.png"), bbox_inches="tight"); plt.close()

# Fig4: unfaithfulness type distribution
types = ["none", "spurious-chain", "post-hoc"]; tcol = {"none": "#8FbC8F", "spurious-chain": "#E8833A", "post-hoc": "#B04A4A"}
data = {t: [sum(1 for r in rows if r["m"] == m and r["ut"] == t) for m in models] for t in types}
fig, ax = plt.subplots(figsize=(6.5, 4.2)); bottom = np.zeros(3)
for t in types:
    ax.bar(mlabel, data[t], bottom=bottom, label=t, color=tcol[t], edgecolor="black", lw=0.5)
    for i, v in enumerate(data[t]):
        if v > 0: ax.text(i, bottom[i] + v / 2, str(v), ha="center", va="center", fontsize=9, fontweight="bold")
    bottom += np.array(data[t])
ax.set_ylabel("count (of 200)"); ax.set_title("Unfaithfulness type distribution", fontweight="bold")
ax.legend(fontsize=9); ax.grid(axis="y", alpha=0.3); plt.tight_layout(); plt.savefig(os.path.join(OUT, "fig4_unfaithful_type.png")); plt.close()

print("Figures written to", OUT)
