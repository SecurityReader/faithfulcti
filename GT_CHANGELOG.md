# Ground-Truth Change Log

Every ground-truth (GT) correction applied during the FaithfulCTI ground-truth audit, with rationale. Each change was made against primary references (NVD, MITRE ATT&CK, CWE corpus, CVSS v3.1 specification) and re-scored without re-querying the models (traces are fixed). Versions are cumulative (v4 → v4c → v4f; the five v4 entries were made under decision DL-043 before re-scoring); the released benchmark is **v4f**.

| Version | Case | Change | Rationale |
| :-- | :-- | :-- | :-- |
| v4 (DL-043) | ADV-CVE-03 | CWE-98 → CWE-646 | item describes a scan scope chosen by file extension and bypass via a non-standard extension; no file-inclusion (CWE-98) mechanism in the text |
| v4 (DL-043) | ADV-CVE-06 | CWE-94 → CWE-787 | item states a missing bounds check leading to an out-of-bounds write; no code-injection mechanism |
| v4 (DL-043) | ADV-CVE-08 | CWE-287 → CWE-306 | item describes a critical function reachable without authentication (missing authentication) rather than improper authentication |
| v4 (DL-043) | ADV-CVE-20 | CWE-78 / CVSS 9.8 → CWE-502 / CVSS 9.8 | root cause is pre-authentication deserialization (CVE-2025-23006); OS command execution is the impact |
| v4 (DL-043) | ADV-CTI-18 | A → B | setuid/setgid distinction (setgid = 2000, setuid = 4000) supports option B; CTIBench key was A |
| v4c | ADV-CTI-12 | D → A | 3 models' clean + main answers all A; distractor target reselected |
| v4c | ADV-CTI-15 | C → D | answer re-adjudication |
| v4c | CVE-N-15 | CWE-94 → CWE-306 | non-typical GT corrected (missing-authentication family) |
| v4c | CTI-M-A07 | + T1660 | technique explicitly in item, missing from GT (parent ID) |
| v4c | CTI-M-A10 | + T1583 | missing technique (parent ID) |
| v4c | CTI-M-A27 | + T1505 | missing technique (parent ID) |
| v4d | CVE-M-03 | 10.0 (CRITICAL) → 7.8 (HIGH) | CVE-2025-24085. Item text (malicious application elevates privileges) implies a local vector; under CVSS 3.1, 10.0 requires AV:N + S:C and the AV:L maximum is 9.3. 7.8 = NVD initial analysis (2025-01-29, AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H). Note: NVD modified analysis on 2025-11-14 changed the vector to AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (10.0), following CISA-ADP (2025-11-12); the original 10.0 GT matches this later record. |
| v4e | CTI-M-A19 | + T1203, T1105, T1140 | item explicitly states CVE exploitation, download, and decoding; omitted from GT (parent IDs) |
| v4f | ADV-CVE-04 | CWE-287 → CWE-288 | NVD classifies CVE-2025-1909 as CWE-288 (authentication bypass by alternate path); original GT was the parent class |

## Audit finding without a change (model error, GT retained)
- **CVE-M-19** (Rack header-parsing DoS): GT = 5.3 (MEDIUM) matches NVD (CVE-2023-27539). All three models over-estimated availability impact to 7.5 (HIGH). GT retained; models scored incorrect. This illustrates that unanimous model disagreement with GT is **not** by itself evidence of a label error.

## Normalization note (ATT&CK)
ATT&CK technique IDs are matched at **parent level** (`T\d{4}`) on both sides; added GT techniques are therefore recorded as parent IDs (e.g., T1583, not T1583.001).

## Annotation-level corrections not yet applied to the test set (pending author decision)
During expert labeling, the annotator judged the reference wrong (gt_quality = wrong-primary) for six further items and labeled correctness against a corrected reference. These corrections are **not** in testset v4f.

| Case | Released GT | Annotator-corrected GT | Note |
| :-- | :-- | :-- | :-- |
| CVE-N-30 | CWE-116 | CWE-150 | item text matches the CWE-150 definition (escape/meta/control sequences) |
| CVE-N-32 | CWE-94 | CWE-23 | item states relative path traversal; code execution is a consequence |
| CVE-N-43 | CWE-787 | CWE-305 | NVD initial classification (CVE-2025-31161); no out-of-bounds write in text |
| CTI-M-A11 | T1429, T1616, T1430, T1655, T1636, T1582, T1422, T1512 | drop T1422 | no network-configuration discovery in item |
| CTI-M-A15 | T1626, T1437, T1532, T1655, T1575, T1406, T1636, T1582, T1426, T1422 | T1626, T1437, T1521, T1655, T1575, T1406, T1636, T1582, T1426 | RC4 used for C2 encryption (T1521), not archiving (T1532); no network-configuration discovery |
| CTI-M-A23 | T1071, T1573, T1090, T1016, T1033 | + T1041, T1571 | exfiltration over C2 and non-standard port stated in item |

## Post-review label correction (not a test-set GT change)
- **CVE-N-15** (GPT-5.6 Sol, Qwen3.5-397B-A17B): the model answer CWE-288 is a child of the corrected reference CWE-306 (CWE 5.0 research view). Under the grading guideline (§III-B) this is a *partial* match, not incorrect. The expert correctness label was regraded incorrect → partial on 2026-11-19 (DL-105). This changes the correctness label only; testset v4f GT (CWE-306) is unchanged, and RQ1/CBU results are unaffected.
