# FaithfulCTI: Answer Accuracy and Rationale Validity Benchmark for CTI and Vulnerability Analysis

FaithfulCTI scores answer *accuracy* and the *validity of the written rationale* separately over 200 CTI/vulnerability items. The main run has 600 expert-labeled responses (200 items × 3 models); the release also contains 120 clean-twin responses, 1,800 voting samples, and 200-response second (reproducibility) runs for all three models.

> Companion artifacts for the paper *"FaithfulCTI: Evaluating Answer Accuracy and Rationale Validity of Large Language Models in Cyber Threat Intelligence and Vulnerability Analysis"* (manuscript in preparation for IEEE Access).

**Released:** 2026-11-26 · **Version:** 1.0.0 · **DOI:** [10.5281/zenodo.24545274](https://doi.org/10.5281/zenodo.24545274)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24545274.svg)](https://doi.org/10.5281/zenodo.24545274)

## Key results (manuscript v2)
- Answer correctness and rationale validity are scored separately for 600 responses (200 items × 3 models).
- Correct answers with an unsupported (T2/T1) rationale: GPT-5.6 Sol 1/133 (0.8%), Claude Haiku 4.5 10/95 (10.5%), Qwen3.5-397B-A17B 15/100 (15.0%); item-level Cochran's Q = 15.1, p = 0.0005.
- 20 of these 26 cases are CVSS items that reach the reference severity band through an unjustified vector or arithmetic error; excluding CVSS, no statistically significant difference among models was found (Q = 3.6, p = 0.17; few events, low power).
- Recomputing stated CVSS vectors (annotator-independent): score–vector inconsistencies in 2/36, 13/31, 17/34 responses.
- Inter-annotator agreement on a stratified 105-response sample: weighted κ = 0.92 (rationale rating), 0.92 (correctness).
- Recompute the computed numbers and Figs. 1–3: `python scripts/reanalysis_v2.py` → `results/reanalysis_v2.json`, `results/cvss_vector_consistency_v2.csv` (error-pattern tags from annotator notes: `results/cvss_cbu_note_tags.csv`).

## Contents
| Path | Description |
| :-- | :-- |
| `benchmark/testset_v4f.json` | 200-case benchmark with audited ground truth |
| `traces/` | Main runs (3 × 200), clean-twin runs (3 × 40), voting runs (3 × 600 samples), second/reproducibility runs (3 × 200, `*_repro2_main.jsonl`), and scored outputs |
| `labels/gold_labels.xlsx`, `labels/rubric.md` | Expert faithfulness gold labels + 4-tier rubric (Korean) |
| `labels/gold_labels_EN.xlsx`, `labels/rubric_EN.md` | English versions of the gold labels and rubric |
| `iaa/` | Inter-annotator agreement package (κ script, adjudication record; `IAA_adjudication_final.xlsx` Korean, `IAA_adjudication_final_EN.xlsx` English) |
| `scripts/` | Scoring, figure, and reproducibility scripts |
| `results/` | Recomputed numbers (`reanalysis_v2.json`), CVSS vector–score consistency, and CVSS CBU annotator notes (`cvss_cbu_note_tags.csv` Korean, `cvss_cbu_note_tags_EN.csv` English) |
| `figures/` | Result figures |
| `GT_CHANGELOG.md` | Ground-truth corrections with rationale |

> **English versions.** The annotator-facing materials were authored in Korean. English translations are provided alongside each (`*_EN` / `rubric_EN.md`): the rubric, the 600-row gold-label workbook (English headers; `note` and category values translated; the redundant Korean reasoning-translation column dropped while the English reasoning original is kept), the 46-row IAA adjudication record, and the 20-row CVSS CBU notes. In case of any discrepancy, the Korean original is authoritative.

## Reproduce
```bash
python scripts/score_traces_v3.py --testset benchmark/testset_v4f.json --traces traces/<model>_main_200_v4.jsonl --out scored.jsonl
python iaa/compute_kappa.py <filled_blind_subset.xlsx>
```

## Models evaluated
GPT-5.6 Sol (frontier, closed), Claude Haiku 4.5 (closed), Qwen3.5-397B-A17B (open MoE). Outputs collected September–October 2026 via provider APIs; exact model identifiers in `benchmark/`.

## Third-party data
MCQ and ATT&CK items reuse CTIBench text verbatim (CTIBench is licensed CC BY-NC-SA 4.0); CWE and CVSS items were written from NVD records (NVD snapshot 2026-06-27). The ATT&CK technique corpus used for the retrieval context blocks is MITRE ATT&CK Enterprise **v19** (April 2026 release; 222 techniques, 475 sub-techniques), frozen as `benchmark/attack_corpus_v19.json` (© MITRE, ATT&CK Terms of Use; see `scripts/fetch_mitre_attack.py` for the pinned version). Files that contain or quote CTIBench text (`benchmark/testset_v4f.json` prompts, `labels/gold_labels.xlsx`, `iaa/IAA_adjudication_final.xlsx`, their English versions `labels/gold_labels_EN.xlsx` and `iaa/IAA_adjudication_final_EN.xlsx`, and model responses in `traces/` that restate item text) are distributed under CC BY-NC-SA 4.0. MITRE ATT&CK, CWE, and NVD content remains subject to its source terms.

## License
Code: Apache-2.0 (`LICENSE`). Original labels and data: CC BY 4.0 (`LICENSE-data`), except files containing CTIBench text, which are CC BY-NC-SA 4.0 (see Third-party data).

## Citation
```bibtex
@article{moon2026faithfulcti,
  title   = {FaithfulCTI: Evaluating Answer Accuracy and Rationale Validity of Large Language Models in Cyber Threat Intelligence and Vulnerability Analysis},
  author  = {Moon, Kwangsuk},
  journal = {IEEE Access (manuscript in preparation)},
  year    = {2026},
  note    = {Code and data: https://github.com/SecurityReader/faithfulcti ; DOI: 10.5281/zenodo.24545274}
}
```
