#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Haiku 재현성 일치율 — 1회차(정본) vs 2회차 최종답 비교 (DL-039).
사용: python compare_repro.py
  1회차: ../../traces/06_v4/haiku45_main_200_v4.jsonl
  2회차: runs/haiku45_repro2_main.jsonl
출력: 전체 일치율 + 과제유형별 + 불일치 케이스 목록.
해석: 95%+ → 비결정성은 GPT/Qwen 개별특성 / 80%안팎 → LLM 전역한계.
의존: 표준 라이브러리만.
"""
import json, re, os
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
RUN1 = os.path.join(HERE, "..", "..", "traces", "06_v4", "haiku45_main_200_v4.jsonl")
RUN2 = os.path.join(HERE, "runs", "haiku45_repro2_main.jsonl")
TESTSET = os.path.join(HERE, "faithfulcti_repro_200.json")

def final_text(raw):
    m = re.search(r"FINAL ANSWER:\s*([^\n]+)", raw or "", re.I)
    return m.group(1).strip() if m else (raw or "")

def norm(kind, raw):
    fa = final_text(raw).upper()
    if kind == "attack": return tuple(sorted(set(re.findall(r"T\d{4}", fa))))
    if kind == "cwe":    return tuple(sorted(set(re.findall(r"CWE-\d+", fa))))
    if kind == "letter":
        m = re.search(r"\b([A-D])\b", fa); return m.group(1) if m else None
    if kind == "band":
        t = re.sub(r"CVSS\s*:?\s*V?3\.\d+", " ", fa)
        m = re.search(r"\b(\d{1,2}(?:\.\d)?)\b", t)
        if m:
            v = float(m.group(1))
            if v == 0: return "NONE"
            if v < 4: return "LOW"
            if v < 7: return "MEDIUM"
            if v < 9: return "HIGH"
            if v <= 10: return "CRITICAL"
        for w in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
            if re.search(r"\b"+w+r"\b", fa): return w
        return None
    return final_text(raw).strip()

def load(path):
    d = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line: continue
        j = json.loads(line)
        d[j["case_id"]] = j.get("raw_response") or ""
    return d

def main():
    if not os.path.exists(RUN2):
        print("2회차 결과 없음:", RUN2, "\n먼저 run_haiku_repro.ps1 실행."); return
    kind = {c["case_id"]: c["answer_kind"] for c in json.load(open(TESTSET, encoding="utf-8"))}
    r1, r2 = load(RUN1), load(RUN2)
    cids = [c for c in kind if c in r1 and c in r2]
    agree = 0; byband = defaultdict(lambda: [0, 0]); mism = []
    for cid in cids:
        k = kind[cid]
        a, b = norm(k, r1[cid]), norm(k, r2[cid])
        byband[k][1] += 1
        if a == b: agree += 1; byband[k][0] += 1
        else: mism.append((cid, k, a, b))
    n = len(cids)
    print(f"Haiku 재현성 (1회차 vs 2회차) — n={n}")
    print(f"★ 전체 최종답 일치율: {agree}/{n} = {100*agree/n:.1f}%")
    print(f"  (참고: GPT 77% · Qwen 80% — DL-036)")
    print(f"  해석: {'비결정성=GPT/Qwen 개별특성, Haiku 기준선' if 100*agree/n>=90 else 'LLM 전역 한계 가능성'}")
    print("\n과제유형별:")
    for k, (h, t) in sorted(byband.items()):
        print(f"  {k:10s} {h}/{t} = {100*h/t:.0f}%")
    print(f"\n불일치 {len(mism)}건:")
    for cid, k, a, b in mism[:40]:
        print(f"  {cid:14s}[{k}] 1회차={a} 2회차={b}")

if __name__ == "__main__":
    main()
