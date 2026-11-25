#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FaithfulCTI v2 re-analysis (response to pre-submission review, 2026-11-19).

Reproduces every number reported in manuscript v2 from released artifacts:
  benchmark/testset_v4f.json, labels/gold_labels.xlsx, traces/*.jsonl, iaa/iaa_105_dual_labels.csv
Outputs:
  results/reanalysis_v2.json      all reported quantities
  results/cvss_vector_consistency_v2.csv per-response CVSS recomputation
  figures/v2_fig1..fig3.png       figures used in manuscript v2
Run from repository root:  python scripts/reanalysis_v2.py
Dependencies: numpy, pandas, openpyxl, matplotlib  (no scipy)
Inference unit: the benchmark item. All three model responses to an item are kept together
(paired design); bootstrap resamples items (B=5000, seed 20261119).
"""
import os, sys, json, math, re, collections
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts")); import score_traces_v3 as S
sys.path.insert(0, os.path.join(ROOT, "iaa")); import compute_kappa as K
P = lambda *a: os.path.join(ROOT, *a)
MS = ["GPT", "Haiku", "Qwen"]
NAME = {"GPT": "GPT-5.6 Sol", "Haiku": "Claude Haiku 4.5", "Qwen": "Qwen3.5-397B-A17B"}
FILE = {"GPT": "gpt56sol", "Haiku": "haiku45", "Qwen": "qwen397b"}
RNG = np.random.default_rng(20261119); B = 5000
R = {}

def wilson(k, n, z=1.959964):
    if n == 0: return (None, None)
    p = k / n; d = 1 + z*z/n; c = p + z*z/(2*n); h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))
    return ((c-h)/d, (c+h)/d)
def chi2_p_df2(x): return math.exp(-x/2)
def ci(a): return [float(np.percentile(a, 2.5)), float(np.percentile(a, 97.5))]

# ---------------- load ----------------
meta = {c["case_id"]: c for c in json.load(open(P("benchmark", "testset_v4f.json"), encoding="utf-8"))}
def base_task(cid):
    u = meta[cid].get("underlying_task") or meta[cid]["task_type"]
    return "CWE" if u.startswith("CVE→CWE") else {"knowledge MCQ": "MCQ", "ATT&CK technique extraction": "ATTACK",
                                                   "CVSS severity reasoning": "CVSS"}[u]
g = pd.read_excel(P("labels", "gold_labels.xlsx"), sheet_name="라벨링")
g.columns = [c.split("(")[-1].rstrip(")") if "(" in str(c) else c for c in g.columns]
g["m"] = g.model.map({"GPT-5.6 Sol": "GPT", "Haiku 4.5": "Haiku", "Qwen 397B": "Qwen"})
g["task"] = g.case_id.map(base_task); g["adv"] = g.is_adv.eq("Y")
g["Y"] = g.gt_match.eq("Y"); g["U"] = g.reasoning_tier.isin(["T1", "T2"]); g["YU"] = g.Y & g.U
def loadj(f):
    d = collections.defaultdict(list)
    for l in open(f, encoding="utf-8"):
        if l.strip(): j = json.loads(l); d[j["case_id"]].append(j)
    return d
def score(cid, raws):
    m = meta[cid]; kind = m["answer_kind"]; norms = [S.normalize(kind, r) for r in raws]
    if norms[0][0] == "set":
        maj, _ = S.consensus_set([n[1] for n in norms], len(norms)); mt = S.set_metrics(maj, m["gt_tokens"])
        h = mt["exact"] if kind == "attack" else mt["anyhit"]
    else:
        maj, _ = S.majority_single([n[1] for n in norms])
        h = maj is not None and str(maj).upper() == str(m["gt_tokens"][0]).upper()
    arr = [x.upper() for x in maj] if isinstance(maj, list) else ([str(maj).upper()] if maj else [])
    anch = bool(m.get("wrong_tokens")) and any(str(w).upper() in arr for w in m["wrong_tokens"])
    return bool(h), (tuple(maj) if isinstance(maj, list) else maj), anch

runs = []; RUNMETA = {}
for m in MS:
    main = loadj(P("traces", f"{FILE[m]}_main_200_v4.jsonl")); ct = loadj(P("traces", f"{FILE[m]}_clean_twin_v4.jsonl"))
    sc = loadj(P("traces", f"{FILE[m]}_sc_200_v4.jsonl"))
    allts = lambda d: [j["ts"] for v in d.values() for j in v]
    RUNMETA[m] = dict(model_id_strings=dict(collections.Counter(j["llm"] for v in main.values() for j in v)),
                      provider=sorted({j["provider"] for v in main.values() for j in v}),
                      main_window=[min(allts(main))[:10], max(allts(main))[:10]],
                      clean_twin_window=[min(allts(ct))[:10], max(allts(ct))[:10]],
                      sc_window=[min(allts(sc))[:10], max(allts(sc))[:10]],
                      sc_temperature_counts=dict(collections.Counter(str(j["temperature"]) for v in sc.values() for j in v)),
                      main_missing_final_answer=sum(1 for v in main.values() for j in v if "FINAL ANSWER" not in (j["raw_response"] or "").upper()),
                      main_empty=sum(1 for v in main.values() for j in v if not (j["raw_response"] or "").strip()),
                      n_main=sum(len(v) for v in main.values()), n_clean=sum(len(v) for v in ct.values()), n_sc=sum(len(v) for v in sc.values()))
    for cid in meta:
        r = dict(m=m, case_id=cid, adv=bool(meta[cid]["is_adv"]), task=base_task(cid), pattern=meta[cid].get("pattern"))
        r["main_hit"], r["main_ans"], r["main_anch"] = score(cid, [j["raw_response"] for j in main[cid]])
        sraw = [j["raw_response"] for j in sc[cid]]
        r["vote_hit"] = score(cid, sraw)[0]; r["s1_hit"] = score(cid, sraw[:1])[0]
        r["sc_single_hits"] = sum(score(cid, [x])[0] for x in sraw)
        if r["adv"]:
            cc = ct["CLEAN-" + cid]
            r["clean_hit"], r["clean_ans"], r["clean_anch"] = score(cid, [j["raw_response"] for j in cc])  # scored vs v4f GT
        runs.append(r)
runs = pd.DataFrame(runs)
R["run_metadata"] = RUNMETA
g = g.merge(runs[["m", "case_id", "main_hit"]], on=["m", "case_id"])

# ---------------- composition ----------------
comp = collections.Counter((meta[c]["band"] if meta[c]["band"] != "CVSS severity reasoning" else "medium",
                            "adversarial" if meta[c]["is_adv"] else "unmodified", base_task(c), meta[c].get("pattern") or "-") for c in meta)
R["composition"] = [dict(band=k[0], condition=k[1], task=k[2], pattern=k[3], n=v) for k, v in sorted(comp.items())]

# ---------------- per-model summary ----------------
summ = {}
for m in MS:
    d = g[g.m == m]
    summ[m] = dict(machine_correct=int(d.main_hit.sum()), expert_Y=int(d.Y.sum()), expert_partial=int((d.gt_match == "partial").sum()),
                   expert_N=int((d.gt_match == "N").sum()), YU=int(d.YU.sum()), YU_cond=float(d.YU.sum()/d.Y.sum()),
                   YU_cond_wilson=wilson(int(d.YU.sum()), int(d.Y.sum())), YU_joint=float(d.YU.mean()),
                   tiers={t: int((d.reasoning_tier == t).sum()) for t in ["T4", "T3", "T2", "T1"]},
                   types={t: int((d.unfaithful_type == t).sum()) for t in ["none", "spurious-chain", "post-hoc"]},
                   machine_vs_expert=pd.crosstab(d.main_hit, d.gt_match).to_dict())
    nonadv = runs[(runs.m == m) & ~runs.adv]; adv = runs[(runs.m == m) & runs.adv]
    summ[m]["acc_by_task_unmodified"] = {t: [int(x.main_hit.sum()), len(x)] for t, x in nonadv.groupby("task")}
    summ[m]["acc_adversarial"] = [int(adv.main_hit.sum()), len(adv)]
R["per_model"] = summ
R["crosstab_gtmatch_tier"] = {m: pd.crosstab(g[g.m == m].gt_match, g[g.m == m].reasoning_tier).to_dict() for m in MS}

# ---------------- RQ1 paired inference ----------------
W = lambda col: g.pivot(index="case_id", columns="m", values=col)[MS].astype(bool)
Y, YU = W("Y"), W("YU"); items = Y.index.values; n = len(items)
def rates(idx):
    y = Y.loc[idx].values; u = YU.loc[idx].values
    return u.sum(0)/np.maximum(y.sum(0), 1), u.mean(0)
c0, j0 = rates(items); bc, bj = [], []
for _ in range(B):
    idx = RNG.choice(items, n, replace=True); c, j = rates(idx); bc.append(c); bj.append(j)
bc, bj = np.array(bc), np.array(bj)
rq1 = dict(conditional={m: dict(est=float(c0[i]), boot_ci=ci(bc[:, i])) for i, m in enumerate(MS)},
           joint={m: dict(est=float(j0[i]), boot_ci=ci(bj[:, i])) for i, m in enumerate(MS)}, differences={})
for a, b in [(1, 0), (2, 0), (2, 1)]:
    rq1["differences"][f"{MS[a]}-{MS[b]}"] = dict(cond=float(c0[a]-c0[b]), cond_ci=ci(bc[:, a]-bc[:, b]),
                                                   joint=float(j0[a]-j0[b]), joint_ci=ci(bj[:, a]-bj[:, b]))
def cochran(X):
    k = X.shape[1]; T = X.sum(1); C = X.sum(0); N = X.sum()
    den = k*N - (T**2).sum()
    Q = (k-1)*(k*(C**2).sum() - N**2)/den if den else 0.0
    return float(Q), chi2_p_df2(Q)
def mcnemar(X, a, b):
    b01 = int(((X[:, a] == 1) & (X[:, b] == 0)).sum()); b10 = int(((X[:, a] == 0) & (X[:, b] == 1)).sum()); nn = b01 + b10
    p = min(1.0, 2*sum(math.comb(nn, i) for i in range(min(b01, b10)+1))/2**nn) if nn else 1.0
    return b01, b10, p
X = YU.values.astype(int)
rq1["cochran_Q_joint"] = cochran(X)
mc = {f"{MS[a]}-{MS[b]}": mcnemar(X, a, b) for a, b in [(1, 0), (2, 0), (2, 1)]}
order = sorted(mc, key=lambda k: mc[k][2]); holm = {}
run = 0
for r_, k in enumerate(order): run = max(run, min(1, mc[k][2]*(3-r_))); holm[k] = run
rq1["mcnemar_exact"] = {k: dict(discordant_a_only=v[0], discordant_b_only=v[1], p=v[2], p_holm=holm[k]) for k, v in mc.items()}
tab = np.array([[YU[m].sum(), Y[m].sum()-YU[m].sum()] for m in MS], float)
E = tab.sum(1, keepdims=True)*tab.sum(0)/tab.sum(); chi = float(((tab-E)**2/E).sum())
rq1["v1_pearson_chi2_reproduced"] = dict(chi2=chi, p=chi2_p_df2(chi), note="treats responses as independent; superseded")
cc = Y.all(1); rq1["common_correct_items"] = dict(n_items=int(cc.sum()), YU={m: int(YU.loc[cc, m].sum()) for m in MS})
task_of = pd.Series({c: base_task(c) for c in items})
rq1["by_task"] = {t: {m: [int(YU.loc[task_of == t, m].sum()), int(Y.loc[task_of == t, m].sum())] for m in MS} for t in ["CVSS", "CWE", "MCQ", "ATTACK"]}
ex = task_of.index[task_of != "CVSS"]
rq1["excluding_CVSS"] = dict(counts={m: [int(YU.loc[ex, m].sum()), int(Y.loc[ex, m].sum())] for m in MS},
                             cochran_Q=cochran(YU.loc[ex].values.astype(int)))
R["RQ1"] = rq1

# ---------------- CVSS vector–score consistency (annotator-independent) ----------------
WT = dict(AV=dict(N=.85, A=.62, L=.55, P=.2), AC=dict(L=.77, H=.44), UI=dict(N=.85, R=.62), CIA=dict(H=.56, L=.22, N=0))
def roundup(x):
    i = round(x*100000); return i/100000.0 if i % 10000 == 0 else (math.floor(i/10000)+1)/10.0
def cvss31(v):
    sc_ = v["S"]; pr = {"N": .85, "L": (.68 if sc_ == "C" else .62), "H": (.5 if sc_ == "C" else .27)}[v["PR"]]
    iss = 1-(1-WT["CIA"][v["C"]])*(1-WT["CIA"][v["I"]])*(1-WT["CIA"][v["A"]])
    imp = 6.42*iss if sc_ == "U" else 7.52*(iss-.029)-3.25*(iss-.02)**15
    ex = 8.22*WT["AV"][v["AV"]]*WT["AC"][v["AC"]]*pr*WT["UI"][v["UI"]]
    if imp <= 0: return 0.0
    return roundup(min(imp+ex, 10)) if sc_ == "U" else roundup(min(1.08*(imp+ex), 10))
allv = [dict(AV=av, AC=ac, PR=p, UI=u, S=s, C=c, I=i, A=a) for av in "NALP" for ac in "LH" for p in "NLH" for u in "NR"
        for s in "UC" for c in "HLN" for i in "HLN" for a in "HLN"]
R["cvss_space"] = dict(n_vectors=len(allv), max_AV_L=max(cvss31(v) for v in allv if v["AV"] == "L"),
                       n_AV_L_critical=sum(1 for v in allv if v["AV"] == "L" and cvss31(v) >= 9.0),
                       score_10_requires=sorted({(v["AV"], v["S"]) for v in allv if cvss31(v) == 10.0}))
rx = re.compile(r"AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])")
cv = []
for m in MS:
    tr = loadj(P("traces", f"{FILE[m]}_main_200_v4.jsonl"))
    for c, mm in meta.items():
        if mm["answer_kind"] != "band" and not mm.get("gt_band"): continue
        raw = tr[c][0]["raw_response"]; fa = S.final_text(raw)
        stated = S.cvss_score(fa if mm["answer_kind"] == "band" else fa.split(";")[-1])
        vs = rx.findall(raw); row = dict(m=m, case_id=c, stated=stated, vector=None, computed=None, consistent=None)
        if vs:
            v = dict(zip(["AV", "AC", "PR", "UI", "S", "C", "I", "A"], vs[-1])); row.update(vector="/".join(vs[-1]), computed=cvss31(v))
            row["consistent"] = stated is not None and abs(row["computed"]-stated) < 0.05
        cv.append(row)
cv = pd.DataFrame(cv).merge(g[["m", "case_id", "gt_match", "reasoning_tier"]], on=["m", "case_id"])
cv["U"] = cv.reasoning_tier.isin(["T1", "T2"])
R["cvss_consistency"] = {m: dict(items=int((cv.m == m).sum()), with_vector=int(cv[cv.m == m].vector.notna().sum()),
                                 consistent=int((cv[cv.m == m].consistent == True).sum()),
                                 inconsistent=int((cv[cv.m == m].consistent == False).sum()),
                                 inconsistent_and_rated_unsupported=int(((cv.m == m) & (cv.consistent == False) & cv.U).sum()),
                                 consistent_and_rated_unsupported=int(((cv.m == m) & (cv.consistent == True) & cv.U).sum()))
                         for m in MS}
hv = cv[cv.vector.notna()]
a = int(((hv.consistent == False) & hv.U).sum()); b_ = int(((hv.consistent == False) & ~hv.U).sum())
c_ = int(((hv.consistent == True) & hv.U).sum()); d_ = int(((hv.consistent == True) & ~hv.U).sum())
R["cvss_consistency_vs_rating"] = dict(inconsistent_U=a, inconsistent_notU=b_, consistent_U=c_, consistent_notU=d_)
cv.to_csv(P("results", "cvss_vector_consistency_v2.csv"), index=False, na_rep="NA")

# ---------------- RQ2: T4 & N audit ----------------
t4n = g[(g.reasoning_tier == "T4") & (g.gt_match == "N")]
R["T4_incorrect"] = [dict(model=r.m, case_id=r.case_id, task=r.task, gt=str(r.ground_truth), answer=str(r.model_answer)[:80],
                          gt_quality=r.gt_quality) for r in t4n.itertuples()]

# ---------------- adversarial paired analysis ----------------
A = runs[runs.adv]; adv = {}
for m in MS:
    a_ = A[A.m == m]; ch = a_.clean_hit.astype(bool); ah = a_.main_hit.astype(bool)
    adv[m] = dict(clean=int(ch.sum()), adversarial=int(ah.sum()), CC=int((ch & ah).sum()), CW=int((ch & ~ah).sum()),
                  WC=int((~ch & ah).sum()), WW=int((~ch & ~ah).sum()), answer_changed=int((a_.main_ans != a_.clean_ans).sum()),
                  anchored_adv=int(a_.main_anch.sum()), anchored_clean=int(a_.clean_anch.sum()),
                  by_pattern={p: dict(n=len(x), clean=int(x.clean_hit.astype(bool).sum()), adv=int(x.main_hit.sum()),
                                      CW=int((x.clean_hit.astype(bool) & ~x.main_hit).sum()), WC=int((~x.clean_hit.astype(bool) & x.main_hit).sum()))
                              for p, x in a_.groupby("pattern")})
    diffs = []
    av = a_.set_index("case_id")
    for _ in range(B):
        idx = RNG.choice(av.index.values, len(av), replace=True)
        diffs.append(av.loc[idx, "main_hit"].astype(int).mean()-av.loc[idx, "clean_hit"].astype(int).mean())
    adv[m]["paired_diff_adv_minus_clean"] = dict(est=(adv[m]["adversarial"]-adv[m]["clean"])/40, boot_ci=ci(diffs))
ga = g[g.adv]
for m in MS:
    d = ga[ga.m == m]
    adv[m]["human_labels"] = dict(cue_mention=d.cue_mention.value_counts().to_dict(), anchored=d.anchored.value_counts().to_dict(),
                                  answer_flip=d.answer_flip.value_counts().to_dict())
R["adversarial"] = adv

# ---------------- self-consistency ----------------
scr = {}
for m in MS:
    for lab, sub in [("adversarial_40", runs[(runs.m == m) & runs.adv]), ("all_200", runs[runs.m == m])]:
        scr.setdefault(m, {})[lab] = dict(main_t0=int(sub.main_hit.sum()), first_sample_t07=int(sub.s1_hit.sum()),
                                          mean_single_t07=float(sub.sc_single_hits.sum()/3), vote_t07=int(sub.vote_hit.sum()),
                                          main_to_vote_gain=int((~sub.main_hit & sub.vote_hit).sum()), main_to_vote_loss=int((sub.main_hit & ~sub.vote_hit).sum()),
                                          s1_to_vote_gain=int((~sub.s1_hit & sub.vote_hit).sum()), s1_to_vote_loss=int((sub.s1_hit & ~sub.vote_hit).sum()))
R["self_consistency"] = scr

# ---------------- run-to-run (only Haiku second run released) ----------------
r1 = {k: v[0]["raw_response"] for k, v in loadj(P("traces", "haiku45_main_200_v4.jsonl")).items()}
r2l = loadj(P("traces", "haiku45_repro2_main.jsonl")); r2 = {k: v[0]["raw_response"] for k, v in r2l.items()}
agr = collections.Counter(); tot = collections.Counter()
for c, mm in meta.items():
    k = mm["answer_kind"]; tot[k] += 1; agr[k] += S.normalize(k, r1[c])[1] == S.normalize(k, r2[c])[1]
R["haiku_rerun"] = dict(agreement=[sum(agr.values()), 200], by_kind={k: [agr[k], tot[k]] for k in tot},
                        rerun_accuracy=sum(score(c, [r2[c]])[0] for c in meta), first_run_accuracy=int(runs[(runs.m == "Haiku")].main_hit.sum()),
                        date=min(j["ts"] for v in r2l.values() for j in v)[:10],
                        note="See rerun_all for the three-model run-to-run comparison.")

# run-to-run for all three models: second run vs the RELEASED first run (*_main_200_v4),
# over all 200 items (an empty/unparsable second-run answer counts as a disagreement).
R["rerun_all"] = {}
for mm_ in MS:
    a1 = {k: v[0]["raw_response"] for k, v in loadj(P("traces", f"{FILE[mm_]}_main_200_v4.jsonl")).items()}
    a2l = loadj(P("traces", f"{FILE[mm_]}_repro2_main.jsonl")); a2 = {k: v[0]["raw_response"] for k, v in a2l.items()}
    ag = collections.Counter(); tt = collections.Counter()
    for c, md in meta.items():
        k = md["answer_kind"]; tt[k] += 1
        ag[k] += (c in a2) and (S.normalize(k, a1[c])[1] == S.normalize(k, a2[c])[1])
    n_same = sum(ag.values()); n_tot = sum(tt.values())
    R["rerun_all"][mm_] = dict(agreement=[n_same, n_tot], pct=round(100.0 * n_same / n_tot, 1),
                               by_kind={k: [ag[k], tt[k]] for k in tt},
                               rerun_accuracy=sum(score(c, [a2[c]])[0] for c in meta if c in a2),
                               first_run_accuracy=int(runs[runs.m == mm_].main_hit.sum()),
                               date=min(j["ts"] for v in a2l.values() for j in v)[:10],
                               basis="second run vs released *_main_200_v4, all 200 items")

# ---------------- IAA ----------------
d = pd.read_csv(P("iaa", "iaa_105_dual_labels.csv")).fillna("")
iaa = dict(n_traces=len(d), n_unique_items=int(d.case_id.nunique()), per_model=d.model.value_counts().to_dict(), fields={})
rng2 = np.random.default_rng(7)
for key, order, wt in [("reasoning_tier", ["T1", "T2", "T3", "T4"], True), ("gt_match", ["N", "partial", "Y"], True),
                       ("unfaithful_type", None, False), ("gt_quality", None, False), ("cue_mention", None, False)]:
    pairs = list(zip(d["A1_"+key], d["A2_"+key])); k_, nv = K.cohen_kappa(pairs, order, wt); bs = []
    for _ in range(2000):
        idx = rng2.integers(0, len(pairs), len(pairs)); kk, _ = K.cohen_kappa([pairs[i] for i in idx], order, wt)
        if kk is not None: bs.append(kk)
    valid = [(a, b) for a, b in pairs if a and b]
    iaa["fields"][key] = dict(kappa=k_, n_valid=nv, boot_ci=ci(bs), raw_agreement=sum(a == b for a, b in valid)/len(valid),
                              disagreements=sum(a != b for a, b in valid), weighted=wt,
                              confusion=pd.crosstab(d["A1_"+key], d["A2_"+key]).to_dict())
bi = lambda s: s.isin(["T1", "T2"]); iaa["binary_tier_agreement"] = float((bi(d.A1_reasoning_tier) == bi(d.A2_reasoning_tier)).mean())
iaa["traces_with_any_disagreement"] = int((d.filter(like="A1_").values != d.filter(like="A2_").values).any(1).sum())
iaa["sample_tier_distribution_A1"] = d.groupby(["model", "A1_reasoning_tier"]).size().unstack().fillna(0).astype(int).to_dict()
R["IAA"] = iaa


# ---------------- additions after second pre-submission check (2026-11-19) ----------------
comp_ids = [c for c in meta if meta[c].get("gt_band")]
ex2 = [c for c in items if task_of[c] != "CVSS" and c not in comp_ids]
R["RQ1"]["excluding_CVSS_and_composite"] = dict(n_items=len(ex2),
    counts={m: [int(YU.loc[ex2, m].sum()), int(Y.loc[ex2, m].sum())] for m in MS},
    cochran_Q=cochran(YU.loc[ex2].values.astype(int)))
# sensitivity: CVE-M-03 reference reverted to 10.0 (all three answers become incorrect; ratings fixed)
Y3 = Y.copy(); Y3.loc["CVE-M-03"] = False; YU3 = Y3 & W("U")
R["RQ1"]["sensitivity_CVE_M_03_10.0"] = dict(counts={m: [int(YU3[m].sum()), int(Y3[m].sum())] for m in MS},
                                              cochran_Q=cochran(YU3.values.astype(int)))
# CBU on standalone CVSS items found by vector recomputation
cbu = g[g.YU & (g.task == "CVSS")][["m", "case_id"]].merge(cv, on=["m", "case_id"], how="left")
R["cvss_cbu_recomputation"] = dict(n=len(cbu), inconsistent=int((cbu.consistent == False).sum()),
                                   consistent=int((cbu.consistent == True).sum()), no_vector=int(cbu.vector.isna().sum()))
# responses without an extractable vector: classify
nov = []
for r in cv[cv.vector.isna()].itertuples():
    raw = loadj(P("traces", f"{FILE[r.m]}_main_200_v4.jsonl"))[r.case_id][0]["raw_response"]
    toks = re.findall(r"\b(?:AV|AC|PR|UI|S|C|I|A|AT):[A-Z]\b", raw)
    kind = "no metric values" if not toks else ("non-v3.1 metric (AT) in vector" if "AT:" in raw else "metric values stated in prose, no vector string")
    nov.append(dict(model=r.m, case_id=r.case_id, kind=kind))
R["cvss_no_vector"] = nov
# voting: first temperature-0.7 sample vs vote, item-level transitions; GPT temperature-0 voting samples
R["self_consistency_transitions_adv"] = {m: dict(s1_to_vote_gain=scr[m]["adversarial_40"]["s1_to_vote_gain"],
                                               s1_to_vote_loss=scr[m]["adversarial_40"]["s1_to_vote_loss"]) for m in MS}
sc_g = loadj(P("traces", "gpt56sol_sc_200_v4.jsonl"))
R["gpt_voting_t0_samples"] = sorted(j["trace_id"] for v in sc_g.values() for j in v if str(j["temperature"]) in ("0", "0.0"))
# ATT&CK recall / F1 (machine, v4f), macro over items
att = {}
for m in MS:
    sc_ = [json.loads(l) for l in open(P("traces", "scored", f"{FILE[m]}_main_200_scored_v4f.jsonl"), encoding="utf-8") if l.strip()]
    for lab, flag in [("unmodified", "False"), ("manipulated", "True")]:
        a_ = [r for r in sc_ if r["answer_kind"] == "attack" and str(r["is_adv"]) == flag]
        att.setdefault(m, {})[lab] = dict(n=len(a_), macro_recall=float(np.mean([float(r["recall"]) for r in a_])),
                                         macro_f1=float(np.mean([float(r["f1"]) for r in a_])))
R["attack_recall_f1"] = att


# answer changes by correctness transition; anchoring with cue mention
A2 = runs[runs.adv].copy(); A2["changed"] = A2.main_ans != A2.clean_ans
A2["tr"] = A2.clean_hit.astype(bool).map({True: "C", False: "W"}) + A2.main_hit.map({True: "C", False: "W"})
R["answer_change_by_transition"] = {k: int(v) for k, v in A2[A2.changed].tr.value_counts().items()}
ga2 = g[g.adv]
R["anchored_with_cue_mention"] = dict(anchored=int((ga2.anchored == "Y").sum()),
                                      anchored_and_cue=int(((ga2.anchored == "Y") & (ga2.cue_mention == "Y")).sum()))


# ---------------- third pre-submission check (2026-11-19) ----------------
# twin vs manipulated run conditions (collection date and logged model string)
cond = {}
for m in MS:
    mn = loadj(P("traces", f"{FILE[m]}_main_200_v4.jsonl")); ct = loadj(P("traces", f"{FILE[m]}_clean_twin_v4.jsonl"))
    same = [c for c in meta if meta[c]["is_adv"] and mn[c][0]["ts"][:10] == ct["CLEAN-" + c][0]["ts"][:10] and mn[c][0]["llm"] == ct["CLEAN-" + c][0]["llm"]]
    diff_id = sum(1 for c in meta if meta[c]["is_adv"] and mn[c][0]["llm"] != ct["CLEAN-" + c][0]["llm"])
    sub = runs[(runs.m == m) & runs.case_id.isin(same)]
    cond[m] = dict(same_date_and_string=len(same), different_string=diff_id,
                   same_condition_clean=int(sub.clean_hit.astype(bool).sum()), same_condition_manipulated=int(sub.main_hit.sum()))
R["twin_run_conditions"] = cond
# voting: single-valued items where all three samples differ (tie broken by first sample)
ties = {}
for m in MS:
    scv = loadj(P("traces", f"{FILE[m]}_sc_200_v4.jsonl")); t = []
    for c, v in scv.items():
        k = meta[c]["answer_kind"]
        if k in ("letter", "band"):
            vals = [S.normalize(k, j["raw_response"])[1] for j in v]
            if len(set(vals)) == len(vals): t.append(c)
    vh = runs[(runs.m == m)].set_index("case_id").vote_hit
    ties[m] = dict(items=t, vote_correct_all200=int(vh.sum()), vote_correct_if_no_majority_wrong=int(vh.sum() - sum(bool(vh[c]) for c in t)),
                   manipulated_items=[c for c in t if meta[c]["is_adv"]])
R["vote_ties"] = ties
# FINAL ANSWER marker variants
mk = {}
for m in MS:
    mn = loadj(P("traces", f"{FILE[m]}_main_200_v4.jsonl")); bold = multi = 0
    for c, v in mn.items():
        t_ = v[0]["raw_response"]
        bold += bool(re.search(r"^\s*\*\*\s*FINAL ANSWER", t_, re.I | re.M)); multi += len(re.findall(r"FINAL ANSWER:", t_, re.I)) > 1
    mk[m] = dict(line_starts_with_bold_marker=bold, more_than_one_marker=multi)
R["final_answer_marker"] = mk


# ---------------- fourth pre-submission check (2026-11-19) ----------------
import itertools
from collections import defaultdict
def cochran_exact(X):
    """Conditional exact p for Cochran's Q: row totals fixed, placements within a row equally likely."""
    rows = [r for r in X if 0 < r.sum() < X.shape[1]]
    if not rows: return 1.0
    q0 = cochran(np.array(rows))[0]; k = X.shape[1]; dist = {tuple([0] * k): 1.0}
    for r in rows:
        sct = int(r.sum()); pls = [pp for pp in itertools.product([0, 1], repeat=k) if sum(pp) == sct]; nd = defaultdict(float)
        for cc, pr in dist.items():
            for pp in pls: nd[tuple(a + b for a, b in zip(cc, pp))] += pr / len(pls)
        dist = nd
    Tt = np.array([r.sum() for r in rows]); N = Tt.sum(); den = k * N - (Tt ** 2).sum()
    return float(sum(pr for cc, pr in dist.items() if (k - 1) * (k * (np.array(cc) ** 2).sum() - N ** 2) / den >= q0 - 1e-9))
R["RQ1"]["cochran_exact_p"] = dict(all_items=cochran_exact(X), excluding_CVSS=cochran_exact(YU.loc[ex].values.astype(int)),
                                   excluding_CVSS_and_composite=cochran_exact(YU.loc[ex2].values.astype(int)))
# ATT&CK partial labels by type (parent-level normalization against v4f)
ann_fixed = {"CTI-M-A11", "CTI-M-A15", "CTI-M-A23"}; pt = defaultdict(int)
for r in g[(g.task == "ATTACK") & (g.gt_match == "partial")].itertuples():
    if r.case_id in ann_fixed: t = "annotator_corrected_reference"
    else:
        Gs = {x[:5] for x in meta[r.case_id]["gt_tokens"]}; Ps = set(re.findall(r"T\d{4}", str(r.model_answer).upper()))
        t = "equal_after_parent_normalization" if Ps == Gs else ("proper_subset_or_superset" if (Ps < Gs or Ps > Gs) else ("overlap_missing_and_extra" if Ps & Gs else "disjoint"))
    pt[f"{r.m}|{t}"] += 1
R["attack_partial_types"] = dict(pt)
# Haiku re-run agreement by logged-string condition
h1 = loadj(P("traces", "haiku45_main_200_v4.jsonl")); h2 = loadj(P("traces", "haiku45_repro2_main.jsonl")); hc = defaultdict(lambda: [0, 0])
for c, mm in meta.items():
    key = "same_string" if h1[c][0]["llm"] == h2[c][0]["llm"] else "different_string"
    hc[key][1] += 1; hc[key][0] += S.normalize(mm["answer_kind"], h1[c][0]["raw_response"])[1] == S.normalize(mm["answer_kind"], h2[c][0]["raw_response"])[1]
R["haiku_rerun_by_string"] = {k: v for k, v in hc.items()}
# CVSS implementation spot checks against published scores
R["cvss_spot_checks"] = {"N/L/N/N/U/H/H/H (9.8)": cvss31(dict(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")),
                         "N/L/N/N/C/H/H/H (10.0)": cvss31(dict(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")),
                         "CVE-2025-24085 initial L/L/N/R/U/H/H/H (7.8)": cvss31(dict(AV="L", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="H")),
                         "CVE-2023-27539 N/L/N/N/U/N/N/L (5.3)": cvss31(dict(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="L"))}

# ---------------- figures ----------------
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "savefig.dpi": 300})
COL = {"GPT": "#1F4E79", "Haiku": "#C55A11", "Qwen": "#7F7F7F"}; HATCH = {"GPT": "", "Haiku": "//", "Qwen": ".."}
tasks = ["MCQ", "CWE", "CVSS", "ATTACK"]; tl = ["Knowledge\nMCQ (n=50)", "CVE→CWE\n(n=50)", "CVSS\n(n=30)", "ATT&CK\n(n=30)"]
fig, ax = plt.subplots(figsize=(3.5, 2.4)); x = np.arange(4); w = .26
for i, m in enumerate(MS):
    vals = [summ[m]["acc_by_task_unmodified"][t] for t in tasks]
    p = [100*k/n for k, n in vals]; lo = [100*(k/n-wilson(k, n)[0]) for k, n in vals]; hi = [100*(wilson(k, n)[1]-k/n) for k, n in vals]
    ax.bar(x+(i-1)*w, p, w, yerr=[lo, hi], capsize=1.5, color=COL[m], hatch=HATCH[m], edgecolor="black", lw=.4, label=NAME[m], error_kw=dict(lw=.6))
ax.set_xticks(x); ax.set_xticklabels(tl, fontsize=7); ax.set_ylabel("Machine-scored accuracy (%)"); ax.set_ylim(0, 105)
ax.legend(fontsize=6, frameon=False, loc="upper right"); ax.grid(axis="y", alpha=.3); plt.tight_layout()
plt.savefig(P("figures", "v2_fig1_accuracy_by_task.png")); plt.close()

fig, ax = plt.subplots(figsize=(3.5, 2.4)); groups = ["CVSS", "non-CVSS"]
for i, m in enumerate(MS):
    vals = [rq1["by_task"]["CVSS"][m], rq1["excluding_CVSS"]["counts"][m]]
    p = [100*k/n if n else 0 for k, n in vals]
    lo = [100*(k/n-wilson(k, n)[0]) if n else 0 for k, n in vals]; hi = [100*(wilson(k, n)[1]-k/n) if n else 0 for k, n in vals]
    bars = ax.bar(np.arange(2)+(i-1)*w, p, w, yerr=[lo, hi], capsize=1.5, color=COL[m], hatch=HATCH[m], edgecolor="black", lw=.4, label=NAME[m], error_kw=dict(lw=.6))
    for j, (k, n) in enumerate(vals): ax.text(j+(i-1)*w, p[j]+hi[j]+1.5, f"{k}/{n}", ha="center", va="bottom", fontsize=5.5)
ax.set_xticks(range(2)); ax.set_xticklabels(["CVSS severity items", "All other items"]); ax.set_ylim(0, 105)
ax.set_ylabel("Correct answers rated T1/T2 (%)"); ax.legend(fontsize=6, frameon=False, loc="upper right", bbox_to_anchor=(1.0, 1.0)); ax.grid(axis="y", alpha=.3); ax.set_ylim(0, 115)
plt.tight_layout(); plt.savefig(P("figures", "v2_fig2_cbu_by_task.png")); plt.close()

fig, axes = plt.subplots(1, 3, figsize=(7.16, 2.1)); tiers = ["T4", "T3", "T2", "T1"]; gms = ["Y", "partial", "N"]
for k_ax, (ax, m) in enumerate(zip(axes, MS)):
    d_ = g[g.m == m]; M = np.array([[int(((d_.gt_match == q) & (d_.reasoning_tier == t)).sum()) for t in tiers] for q in gms])
    im = ax.imshow(M, cmap="Greys", vmin=0, vmax=140, aspect="auto")
    ax.set_xticks(range(4)); ax.set_xticklabels(tiers); ax.set_yticks(range(3)); ax.set_yticklabels(["Correct", "Partial", "Incorrect"] if k_ax == 0 else [])
    for i in range(3):
        for j in range(4): ax.text(j, i, M[i, j], ha="center", va="center", fontsize=8, color="white" if M[i, j] > 70 else "black")
    ax.set_title(NAME[m], fontsize=8); ax.set_xlabel("Rationale rating")
cb = fig.colorbar(im, ax=axes, fraction=.02, pad=.02); cb.set_label("Responses (count)", fontsize=7)
plt.savefig(P("figures", "v2_fig3_crosstab.png"), bbox_inches="tight"); plt.close()


# column-width version used in manuscript v2 (Fig. 3)
plt.rcParams.update({"font.size": 6})
fig, axes = plt.subplots(1, 3, figsize=(3.5, 1.45), sharey=True)
for ax, m in zip(axes, MS):
    d_ = g[g.m == m]; M = np.array([[int(((d_.gt_match == q) & (d_.reasoning_tier == t)).sum()) for t in tiers] for q in gms])
    ax.imshow(M, cmap="Greys", vmin=0, vmax=140, aspect="auto")
    ax.set_xticks(range(4)); ax.set_xticklabels(tiers); ax.set_yticks(range(3)); ax.set_yticklabels(["Correct", "Partial", "Incorrect"])
    for i in range(3):
        for j in range(4): ax.text(j, i, M[i, j], ha="center", va="center", fontsize=6, color="white" if M[i, j] > 70 else "black")
    ax.set_title(NAME[m], fontsize=6); ax.tick_params(length=1.5, pad=1)
fig.supxlabel("Rationale rating (shading: count, 0–140)", fontsize=6, y=0.02)
plt.tight_layout(pad=0.3, w_pad=0.4); plt.savefig(P("figures", "v2_fig3_crosstab_col.png"), dpi=400); plt.close()

# ---------------- write ----------------
def conv(o):
    if isinstance(o, (np.integer,)): return int(o)
    if isinstance(o, (np.floating,)): return float(o)
    if isinstance(o, (np.bool_,)): return bool(o)
    if isinstance(o, tuple): return list(o)
    return str(o)
def keyfix(o):
    if isinstance(o, dict): return {str(k): keyfix(v) for k, v in o.items()}
    if isinstance(o, list): return [keyfix(v) for v in o]
    return o
json.dump(keyfix(R), open(P("results", "reanalysis_v2.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=conv)
print(json.dumps(keyfix({k: R[k] for k in ["RQ1", "cvss_space", "cvss_consistency", "cvss_consistency_vs_rating", "haiku_rerun"]}), default=conv, indent=1)[:6000])
print("written results/reanalysis_v2.json")
