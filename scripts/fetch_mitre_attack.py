#!/usr/bin/env python3
"""MITRE ATT&CK Enterprise STIX 다운로드 + technique 코퍼스 추출.

재현성: 본 연구가 사용한 판본은 ATT&CK Enterprise v19(2026-04-28 릴리스, 기법 222·하위기법 475)이며
2026-07-02에 당시 master에서 내려받았다. 재현을 위해 master가 아니라 아래의 고정 버전 URL을 사용한다.
(원 수집 당시 스크립트는 .../master/enterprise-attack/enterprise-attack.json 을 사용했음)
"""
import urllib.request, json, os
os.makedirs("raw/mitre",exist_ok=True)
ATTACK_VERSION = "19.0"  # v19 (April 2026 release); counts 222/475 match raw/mitre/attack_techniques.json.
                         # 2026-07-02 수집 당시 master의 v19 라인(포인트 릴리스는 별도 기록 없음).
URL=f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
urllib.request.urlretrieve(URL,"raw/mitre/enterprise-attack.json")
d=json.load(open("raw/mitre/enterprise-attack.json"))
techs=[]
for o in d["objects"]:
    if o.get("type")=="attack-pattern" and not o.get("x_mitre_deprecated") and not o.get("revoked"):
        tid=next((r.get("external_id","") for r in o.get("external_references",[]) if r.get("source_name")=="mitre-attack"),"")
        if tid: techs.append({"technique_id":tid,"name":o.get("name",""),
                 "tactics":[p["phase_name"] for p in o.get("kill_chain_phases",[])],
                 "description":(o.get("description","") or "")[:800],
                 "is_subtechnique":o.get("x_mitre_is_subtechnique",False)})
json.dump(techs, open("raw/mitre/attack_techniques.json","w"), ensure_ascii=False, indent=1)
print("techniques:",len(techs))
