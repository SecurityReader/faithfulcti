# ============================================================================
# FaithfulCTI Haiku 재현성 측정 (DL-039) — temp=0 동일조건 2회차
#   목적: Haiku 케이스단위 최종답 변동률 측정(GPT 77%·Qwen 80% 기측정, Haiku 미측정)
#   결과 해석(DL-039): 95%+ → 비결정성은 GPT/Qwen 개별특성 / 80%안팎 → LLM 전역한계
# ============================================================================
# 입력: faithfulcti_repro_200.json (정본 v4f 프롬프트 200케이스)
# 출력: runs\haiku45_repro2_main.jsonl  (1회차=traces/06_v4/haiku45_main_200_v4.jsonl 와 비교)
# 실행조건: main 동일 — N=1, temperature=0, max_tokens=2048, --require_final
# 사용:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\run_haiku_repro.ps1 -DryRun     # 계획 확인
#   .\run_haiku_repro.ps1             # Anthropic 키 입력
#   .\run_haiku_repro.ps1 -MaxTok 6144  # 빈응답 재시도 시
# 이 파일은 UTF-8 with BOM 으로 저장됨.
# ============================================================================
param([int]$MaxTok=2048,[switch]$DryRun)

$SET    = Join-Path $PSScriptRoot "faithfulcti_repro_200.json"
$RUNNER = Join-Path $PSScriptRoot "..\..\model_test_kit\run_model.py"
$OUT    = Join-Path $PSScriptRoot "runs"
New-Item -ItemType Directory -Force -Path $OUT | Out-Null
foreach ($f in @($RUNNER,$SET)) { if (-not (Test-Path $f)) { Write-Host "없음: $f" -ForegroundColor Red; exit 1 } }

$name="claude-haiku-4-5-20251001"
$outfile = Join-Path $OUT "haiku45_repro2_main.jsonl"
Write-Host "[Haiku 4.5] repro2_main  N=1 temp=0 cap=$MaxTok -> $outfile" -ForegroundColor Cyan
if ($DryRun) { Write-Host "DryRun 종료" -ForegroundColor Yellow; exit 0 }

$sec = Read-Host "Anthropic API Key 입력 (Haiku 4.5)" -AsSecureString
$key = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
$env:MODEL_PROVIDER="anthropic"; $env:MODEL_BASE_URL="https://api.anthropic.com/v1"
$env:MODEL_ID=$name; $env:MODEL_API_KEY=$key
Remove-Item Env:\MODEL_EXTRA_JSON -ErrorAction SilentlyContinue

python $RUNNER --testset $SET --out $outfile --name $name `
    --samples 1 --temperature 0 --max_tokens $MaxTok --require_final
Write-Host "완료 → $outfile" -ForegroundColor Green
Write-Host "다음: python compare_repro.py" -ForegroundColor Green
