# 공개 저장소 폴더 — 준비 메모

이 폴더(`github_repo_faithfulcti/`)는 GITHUB_RELEASE_GUIDE.md의 권장 구조대로 구성한 **공개용 스냅샷**입니다. 그대로 GitHub repo로 올리면 됩니다(절차는 가이드 §5).

## 올리기 전 로컬에서 할 정리 1가지
`figures/`에 **구 파일명 중복 4개**가 있습니다(샌드박스 권한으로 자동삭제 불가). 로컬에서 아래를 삭제하세요:
- fig1_unfaithful_correct.png
- fig2_crosstab_heatmap.png
- fig3_unfaithful_type.png
- fig4_accuracy_by_band.png

**유지할 올바른 4개(최종 번호 일치)**:
- fig1_accuracy_by_band.png
- fig2_unfaithful_correct.png
- fig3_crosstab_heatmap.png
- fig4_unfaithful_type.png

(또는 `python scripts/make_figures.py`로 올바른 4개를 재생성 가능.)

## 라이선스
LICENSE(코드 Apache-2.0) 전문은 GitHub "Add license template"로 삽입 권장. LICENSE-data(CC BY 4.0) 포함.

## κ 재현
`python iaa/compute_kappa.py` → iaa/iaa_105_dual_labels.csv에서 κ 재계산(논문값 재현).

## results/cvss_vector_consistency_v2.csv — NA convention
Columns: m, case_id, stated, vector, computed, consistent, gt_match, reasoning_tier, U.
`vector`/`computed`/`consistent` = `NA` means the response stated no extractable CVSS vector
(7 responses: 0 GPT, 5 Claude Haiku 4.5, 2 Qwen), so the arithmetic self-consistency check is
undefined for them; see Section VI-C ("Seven responses had no extractable vector"). This matches
Table VI "Responses stating a vector" = 36 / 31 / 34. These rows are not score errors and are not
part of the 20 standalone-CVSS CBU decomposition in Table VII.
