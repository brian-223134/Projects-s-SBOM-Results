# SBOM Analyze (code/analyze)

이 디렉토리는 **SBOM 산출물(JSON 등)을 파싱/정규화**하고, 특히 Go 프로젝트에 대해 **`go.mod` 기반 ground truth(GT)** 를 추출한 뒤 **SBOM 도구 결과와 비교(검증)** 하는 스크립트/출력물을 모아둡니다.

## Contents

- `go_mod_gt.py`: `go.mod` 파일을 스캔하여 GT를 JSON/CSV로 추출
- `go_sbom_gt_validate.py`: CycloneDX SBOM을 GT와 비교하여 TP/FP/FN 및 지표를 계산
- `SBOM_parser.py`, `SBOM_purl.py`, `SBOM_scheme.py`: SBOM 파싱/스키마/식별자(purl) 관련 모듈
- `out/`: 분석 결과 산출물(스크립트 실행 결과)이 저장되는 폴더

---

## 1) Go 의존성(GT) 추출: `go_mod_gt.py`

### 무엇을 추출하나?

프로젝트 하위의 모든 `go.mod`를 찾아서 **선언된(declared) 의존성 신호**를 뽑습니다.

- `module`: 루트 모듈 경로
- `go`: Go 버전
- `require`: 의존 모듈 + 버전
  - `// indirect` 주석 여부로 direct/indirect 구분
  - `require (...)` 블록과 단일 라인(`require a b`) 모두 처리
- `replace`: 모듈/버전 치환 규칙
- `tool`: 도구 의존성(있는 경우)

### 산출물

`--out-dir` 아래에 다음 파일이 생성됩니다.

- `go_mod_gt.json`: 각 `go.mod`의 파싱 결과(원본에 가까운 구조)
- `go_mod_requires.csv`: require를 테이블로 평탄화한 결과
- `go_mod_replaces.csv`: replace 테이블
- `go_mod_tools.csv`: tool 테이블

### 실행 예시 (Terraform)

```powershell
C:/Users/{username}/Desktop/Projects-s-SBOM-Results/.venv/Scripts/python.exe code/analyze/go_mod_gt.py `
  --root languages/go/project/terraform `
  --out-dir code/analyze/out/go-gt-terraform
```

---

## 2) SBOM vs GT 검증: `go_sbom_gt_validate.py`

### 입력

- GT 디렉토리: `go_mod_gt.py`가 만든 폴더(내부에 `go_mod_gt.json` 필요)
- SBOM 파일: CycloneDX JSON (예: cdxgen/syft/trivy 결과)

### 비교 방식(요약)

- GT(expected set): `go_mod_gt.json`의 `requires`를 기반으로 `(module, version)` 집합 구성
- SBOM(observed set): CycloneDX `components[]`에서 `purl`(우선) 또는 `(name, version)`(fallback)로 `(module, version)` 집합 구성
- 결과: 집합 비교로 TP/FP/FN 산출

> 참고: SBOM의 Go purl은 보통 `pkg:golang/<module>@<version>` 형태입니다.

### 출력

`--out-dir` 아래에 다음 파일이 생성됩니다.

- `summary.json`: SBOM별 TP/FP/FN 및 지표(precision/recall/F1/accuracy_union) 요약
- `<sbom_stem>.tp.csv`: TP 목록
- `<sbom_stem>.fp.csv`: FP 목록
- `<sbom_stem>.fn.csv`: FN 목록
- `<sbom_stem>.fp_triage.csv`: FP를 원인(reason)으로 분류한 목록

### 실행 예시 (Terraform)

```powershell
& "C:/Users/{username}/Desktop/Projects-s-SBOM-Results/.venv/Scripts/python.exe" \
  "code/analyze/go_sbom_gt_validate.py" \
  --gt-dir "code/analyze/out/go-gt-terraform" \
  --sbom "languages/go/SBOM/terraform/cdxgen/terraform_cdxgen_sbom.json" \
  --sbom "languages/go/SBOM/terraform/syft/terraform_syft_sbom.json" \
  --sbom "languages/go/SBOM/terraform/trivy/terraform_trivy_sbom.json" \
  --out-dir "code/analyze/out/go-gt-terraform/validation"
```

---

## out/ 디렉토리 구조

예: `code/analyze/out/go-gt-terraform/`

- `go_mod_gt.json`: `go.mod` 스캔 결과(원본 구조)
- `go_mod_requires.csv`: require 테이블
- `go_mod_replaces.csv`: replace 테이블
- `go_mod_tools.csv`: tool 테이블
- `validation/`
  - `summary.json`: 도구별 요약 지표
  - `terraform_{tool}_sbom.tp.csv|fp.csv|fn.csv`: 도구별 TP/FP/FN 목록
  - `terraform_{tool}_sbom.fp_triage.csv`: FP 분류 결과

---

## Metric notes

- `precision` = $\frac{TP}{TP+FP}$
- `recall` = $\frac{TP}{TP+FN}$
- `F1` = $\frac{2TP}{2TP+FP+FN}$
- `accuracy_union` = $\frac{TP}{|GT \cup SBOM|}$
  - SBOM 비교에서는 TN(true negative)이 잘 정의되지 않으므로, 합집합 기반(Jaccard-style) 지표를 사용합니다.
