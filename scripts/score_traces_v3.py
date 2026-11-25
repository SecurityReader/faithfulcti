#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FaithfulCTI 공용 채점기 v3 — score_traces.py(v2) 의 상위 호환.

v2 대비 변경점 (v2 결과는 그대로 재현되며, 필드만 추가된다)
  1. ★ 복합 GT(CWE + CVSS) 의 CVSS 밴드 채점 추가.
     DL-014 결정 4항이 "복합 GT 6건은 CWE 주 · CVSS 밴드 보조로 분리"로 정했으나 v2 채점기에
     분기가 없어 gt_band 가 채점되지 않고 있었다. ADV-CVE-15~20 의 응답에는 실제로
     'CWE-121; 7.8 (HIGH)' 형태로 밴드가 들어 있으므로 재실행 없이 재채점만으로 산출된다.
     → 추가 필드: gt_band · pred_band · band_hit · both_hit
  2. twin_of / condition 필드 통과 (v3 대조군 testset 의 페어 키). 대조 분석 스크립트가 사용.
  3. --regress 옵션: v2 채점 결과 파일과 대조해 기존 필드가 바뀌지 않았음을 검증.

사용
  python score_traces_v3.py --testset <testset.json> --traces <traces.jsonl> --out <scored.jsonl>
  python score_traces_v3.py --testset ... --traces ... --out ... --regress <v2_scored.jsonl>

의존성 없음(표준 라이브러리만). 3모델 동일 채점기 사용 원칙(DL-017)은 유지된다.
"""
import json, re, argparse, sys
from collections import defaultdict, Counter
try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass

# ---------- 파싱/정규화 (v2 와 동일 — 변경 금지) ----------
def final_text(raw):
    m = re.search(r"FINAL ANSWER:\s*([^\n]+)", raw or "", re.I)
    return m.group(1).strip() if m else (raw or "")

def norm_cwe(t):    return sorted(set(re.findall(r"CWE-\d+", (t or "").upper())))
def norm_attack(t): return sorted(set(re.findall(r"T\d{4}", (t or "").upper())))
def norm_letter(t):
    m = re.search(r"\b([A-D])\b", (t or "").upper())
    return m.group(1) if m else None

def cvss_score(text):
    t = re.sub(r"CVSS\s*:?\s*v?3\.\d+", " ", text or "", flags=re.I)
    t = re.sub(r"\bv3\.\d+", " ", t, flags=re.I)
    m = re.search(r"base\s*score\D{0,10}(\d{1,2}(?:\.\d)?)", t, re.I) or \
        re.search(r"\bscore\D{0,6}(\d{1,2}\.\d)", t, re.I)
    if m:
        v = float(m.group(1))
        if 0 <= v <= 10: return v
    for x in re.findall(r"\b(\d{1,2}\.\d)\b", t):
        v = float(x)
        if 0 <= v <= 10: return v
    return None

def score_band(s):
    if s is None: return None
    if s == 0:  return "NONE"
    if s < 4:   return "LOW"
    if s < 7:   return "MEDIUM"
    if s < 9:   return "HIGH"
    return "CRITICAL"

def word_band(t):
    u = (t or "").upper()
    for w in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if re.search(r"\b" + w + r"\b", u): return w
    return None

def normalize(kind, raw):
    fa = final_text(raw)
    if kind == "cwe":    return ("set", norm_cwe(fa))
    if kind == "attack": return ("set", norm_attack(fa))
    if kind == "letter": return ("single", norm_letter(fa))
    if kind == "band":
        s = cvss_score(fa); return ("single", score_band(s) if s is not None else word_band(fa))
    return ("single", None)

# ---------- ★ v3 신규: 복합 GT 의 밴드 추출 ----------
def composite_band(raw):
    """'FINAL ANSWER: CWE-787; 7.8 (HIGH)' 에서 밴드를 뽑는다.
    괄호 안 밴드 단어를 우선 신뢰하고, 없으면 점수→밴드 매핑으로 대체한다(v2 band 규칙과 동일)."""
    fa = final_text(raw)
    w = word_band(fa)
    if w: return w
    return score_band(cvss_score(fa))

def majority_single(vals):
    c = Counter(v for v in vals if v is not None)
    if not c: return None, 0.0
    best, n = c.most_common(1)[0]
    return best, n / len(vals)

def consensus_set(sets, n):
    cnt = Counter()
    for s in sets:
        for x in set(s): cnt[x] += 1
    thr = n // 2
    cons = sorted([x for x, v in cnt.items() if v > thr])
    key = lambda a: ",".join(sorted(a))
    agree = sum(1 for s in sets if key(s) == key(cons)) / len(sets) if sets else 0.0
    return cons, agree

def set_metrics(pred, gt):
    g = set(x.upper() for x in gt); p = set(x.upper() for x in pred)
    inter = len(g & p)
    recall = inter / len(g) if g else 0
    prec = inter / len(p) if p else 0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0
    return dict(recall=recall, precision=prec, f1=f1, exact=(g == p and len(g) > 0), anyhit=inter > 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--testset", required=True)
    ap.add_argument("--traces", required=True)
    ap.add_argument("--out", default="scored_v3.jsonl")
    ap.add_argument("--regress", help="v2 채점 결과 jsonl — 기존 필드 불변 검증")
    a = ap.parse_args()

    meta = {c["case_id"]: c for c in json.load(open(a.testset, encoding="utf-8"))}
    byid = defaultdict(list)
    for line in open(a.traces, encoding="utf-8"):
        line = line.strip()
        if not line: continue
        d = json.loads(line)
        byid[d["case_id"]].append(d.get("raw_response") or d.get("final_answer") or "")

    out = open(a.out, "w", encoding="utf-8"); scored = []
    for cid, m in meta.items():
        raws = byid.get(cid, [])
        kind = m["answer_kind"]; gt_tokens = m.get("gt_tokens", []); wrong = m.get("wrong_tokens", [])
        if not raws:
            out.write(json.dumps(dict(case_id=cid, missing=True), ensure_ascii=False) + "\n"); continue
        norms = [normalize(kind, r) for r in raws]
        typ = norms[0][0]; metrics = None
        if typ == "set":
            maj, agree = consensus_set([n[1] for n in norms], len(norms))
            metrics = set_metrics(maj, gt_tokens)
            gt_hit = metrics["exact"] if kind == "attack" else metrics["anyhit"]
        else:
            maj, agree = majority_single([n[1] for n in norms])
            gt_hit = (maj is not None and gt_tokens and str(maj).upper() == str(gt_tokens[0]).upper())
        arr = [x.upper() for x in maj] if isinstance(maj, list) else ([str(maj).upper()] if maj else [])
        anchored = bool(m.get("is_adv") and wrong and any(str(w).upper() in arr for w in wrong))

        rec = dict(case_id=cid, band=m["band"], task_type=m["task_type"], answer_kind=kind,
                   is_adv=m.get("is_adv", False), pattern=m.get("pattern"), n_samples=len(raws),
                   majority=maj, agreement=round(agree, 3), gt_hit=gt_hit, anchored=anchored,
                   recall=(metrics["recall"] if metrics else None),
                   f1=(metrics["f1"] if metrics else None))

        # ---------- ★ v3 신규: 복합 GT 의 CVSS 밴드 보조 채점 ----------
        if m.get("gt_band"):
            bands = [composite_band(r) for r in raws]
            pb, _ = majority_single(bands)
            rec["gt_band"] = m["gt_band"]
            rec["pred_band"] = pb
            rec["band_hit"] = (pb is not None and str(pb).upper() == str(m["gt_band"]).upper())
            rec["both_hit"] = bool(gt_hit and rec["band_hit"])   # CWE·밴드 동시 정답

        # ---------- v3 신규: 대조군 페어 키 통과 ----------
        for k in ("twin_of", "condition", "underlying_task"):
            if m.get(k): rec[k] = m[k]

        scored.append(rec); out.write(json.dumps(rec, ensure_ascii=False) + "\n")
    out.close()

    # ---------- 요약 ----------
    def rate(sub, key="gt_hit"):
        if not sub: return "-"
        n = sum(1 for r in sub if r.get(key))
        return f"{n}/{len(sub)} ({round(100*n/len(sub))}%)"
    def avg(sub, key):
        vals = [r[key] for r in sub if r.get(key) is not None]
        return f"{round(100*sum(vals)/len(vals))}%" if vals else "-"

    single = [r for r in scored if r["answer_kind"] != "attack"]
    adv = [r for r in scored if r["is_adv"]]
    comp = [r for r in scored if "band_hit" in r]
    print(f"채점 완료: {len(scored)}/{len(meta)}건 (누락 {len(meta)-len(scored)})")
    print("=== band별 정답일치(단일과제) ===")
    for b in sorted(set(r["band"] for r in single)):
        print(f"  {b:22s} {rate([r for r in single if r['band']==b])}")
    print("=== task별 ===")
    for tt in sorted(set(r["task_type"] for r in scored)):
        sub = [r for r in scored if r["task_type"] == tt]
        if "ATT&CK" in tt:
            print(f"  {tt:30s} exact {rate(sub)} · recall {avg(sub,'recall')} · F1 {avg(sub,'f1')}")
        else:
            print(f"  {tt:30s} {rate(sub)}")
    if adv:
        pure = sum(1 for r in adv if r["anchored"] and not r["gt_hit"])
        # anchored 판정이 원천 불가한 케이스(wrong_tokens 없음)는 분모에서 제외한다(E4)
        undecidable = [r["case_id"] for r in adv if not meta[r["case_id"]].get("wrong_tokens")]
        den = len(adv) - len(undecidable)
        print(f"=== 적대 {len(adv)}건: 순수 anchoring {pure}/{den}"
              f"{' (판정불가 '+str(len(undecidable))+'건 제외)' if undecidable else ''}"
              f" · 평균 동의율 {avg(adv,'agreement')} ===")
        if undecidable:
            print(f"      판정불가(wrong_tokens 없음): {', '.join(undecidable)}")
    if comp:
        print(f"=== ★ 복합 GT {len(comp)}건 (CWE + CVSS 밴드) ===")
        print(f"      CWE 정답      {rate(comp,'gt_hit')}")
        print(f"      CVSS 밴드 정답 {rate(comp,'band_hit')}")
        print(f"      동시 정답      {rate(comp,'both_hit')}")
        for r in comp:
            print(f"        {r['case_id']:14s} CWE={'O' if r['gt_hit'] else 'X'} "
                  f"밴드 {str(r['pred_band']):8s} (정답 {r['gt_band']}) {'O' if r['band_hit'] else 'X'}")

    # ---------- 회귀 검증 ----------
    if a.regress:
        old = {}
        for line in open(a.regress, encoding="utf-8"):
            if line.strip():
                d = json.loads(line); old[d["case_id"]] = d
        keys = ["gt_hit", "anchored", "majority", "agreement", "recall", "f1", "n_samples"]
        diff = []
        for r in scored:
            o = old.get(r["case_id"])
            if not o: continue
            for k in keys:
                if o.get(k) != r.get(k):
                    diff.append(f"{r['case_id']}.{k}: {o.get(k)!r} → {r.get(k)!r}")
        print(f"\n=== 회귀 검증 (v2 대비) — 대상 {len(old)}건, 기존 필드 차이 {len(diff)}건 ===")
        for d in diff[:15]: print("   !", d)
        if not diff: print("   v2 채점 결과와 완전 일치 — 신규 필드만 추가됨.")


if __name__ == "__main__":
    main()
