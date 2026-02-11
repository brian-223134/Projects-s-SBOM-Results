# SBOM Analyze (code/analyze)

이 디렉토리는 **SBOM 산출물(JSON 등)을 파싱/정규화**하고, 특히 Go 프로젝트에 대해 **`go.mod` 기반 ground truth(GT)** 를 추출한 뒤 **SBOM 도구 결과와 비교(검증)** 하는 스크립트/출력물을 모아둡니다.

## Contents

- `go_mod_gt.py`: `go.mod` 파일을 스캔하여 GT를 JSON/CSV로 추출
- `go_sbom_gt_validate.py`: CycloneDX SBOM을 GT와 비교하여 TP/FP/FN 및 지표를 계산
- `php_js_lock_gt.py`: Composer(`composer.lock`) + npm(`package-lock.json`) lockfile 기반 GT를 JSON/CSV로 추출
- `php_js_sbom_gt_validate.py`: CycloneDX SBOM(cdxgen/syft/trivy)의 composer/npm purl을 GT와 비교
- `SBOM_parser.py`, `SBOM_purl.py`, `SBOM_scheme.py`: SBOM 파싱/스키마/식별자(purl) 관련 모듈
- `out/`: 분석 결과 산출물(스크립트 실행 결과)이 저장되는 폴더

## Java (DBeaver) - Maven GT & SBOM 검증

Go는 `go.mod`에서 GT를 직접 뽑을 수 있지만, DBeaver처럼 Tycho(OSGi/P2) 기반인 Java 프로젝트는 단일 "정답 파일"이 명확하지 않을 수 있습니다.
그래서 **Trivy CycloneDX SBOM을 후보 풀(candidate pool)** 로 삼고, **로컬 pom.xml 스캔으로 내부(reactor) 모듈을 제외**하여 재현 가능한 Maven GT를 만듭니다.

### 1) Trivy SBOM → Maven GT 추출

- 스크립트: `java_trivy_gt_extract.py`
- 출력(예: `code/analyze/out/java-gt-dbeaver/`)
  - `expected_maven_all.csv|json`: 최종 GT(내부 reactor 산출물 포함)
  - `expected_maven_external.csv|json`: 외부 Maven만 남긴 GT(프로젝트 특성상 비어 있을 수 있음)
  - `internal_modules.json`: pom.xml 기반 내부 모듈 목록
  - `gt_candidates_from_trivy.json`: SBOM에서 파싱된 Maven 후보 전체
  - `filters_report.json`: 제외 사유별 카운트

```powershell
python code/analyze/java_trivy_gt_extract.py \
  --project-root languages/java/project/dbeaver \
  --sbom languages/java/SBOM/dbeaver/trivy/dbeaver_trivy_sbom.json \
  --out-dir code/analyze/out/java-gt-dbeaver
```

### 2) GT ↔ SBOM 검증(TP/FP/FN)

- 스크립트: `java_sbom_gt_validate.py`

```powershell
python code/analyze/java_sbom_gt_validate.py \
  --gt code/analyze/out/java-gt-dbeaver/expected_maven_all.csv \
  --sbom languages/java/SBOM/dbeaver/trivy/dbeaver_trivy_sbom.json \
  --sbom languages/java/SBOM/dbeaver/syft/dbeaver_syft_sbom.json \
  --sbom languages/java/SBOM/dbeaver/cdxgen/dbeaver_cdxgen_sbom.json \
  --out-dir code/analyze/out/java-gt-dbeaver/validation

참고: DBeaver 같은 Tycho 기반 프로젝트에서 cdxgen SBOM은 Maven 좌표를 상대적으로 적게 담을 수 있습니다.
```

---

---

## PHP (Coolify) - Composer+npm lockfile GT & SBOM 검증

Coolify는 PHP(Composer) + JS(npm) 혼합 프로젝트이며, **정답(ground truth)은 lockfile 기반**으로 만드는 것이 가장 재현성이 좋습니다.

- Composer: `composer.lock`의 resolved 패키지(`packages`, `packages-dev`)
  - `composer.json`의 `require`/`require-dev`를 참고해 direct/dev-direct 표기(보조)
  - `php`, `ext-*`, `lib-*` 등 플랫폼 항목은 제외
- npm: `package-lock.json`(lockfileVersion 3)의 `packages` 맵에서 resolved 패키지
  - `packages[""]`의 `dependencies`/`devDependencies`를 참고해 direct/dev-direct 표기(보조)
  - `link: true` 항목은 제외

### 입력 파일(이번 실험: coolify)

- Composer
  - `languages/php/project/coolify/composer.json`
  - `languages/php/project/coolify/composer.lock`
- npm
  - `languages/php/project/coolify/package.json`
  - `languages/php/project/coolify/package-lock.json`
  - `languages/php/project/coolify/docker/coolify-realtime/package.json`
  - `languages/php/project/coolify/docker/coolify-realtime/package-lock.json`

### 1) Lockfile 기반 GT 생성

- 스크립트: `php_js_lock_gt.py`
- 출력(예: `code/analyze/out/php-js-gt-coolify/`)
  - `php_js_lock_gt.json`: 최종 GT(JSON)
  - `composer_deps.csv`: composer 의존성 테이블
  - `npm_deps.csv`: npm 의존성 테이블

```powershell
python code/analyze/php_js_lock_gt.py \
  --root languages/php/project/coolify \
  --out-dir code/analyze/out/php-js-gt-coolify
```

### 2) GT ↔ CycloneDX SBOM 검증(TP/FP/FN)

- 스크립트: `php_js_sbom_gt_validate.py`
- 입력 SBOM(CycloneDX JSON)
  - `languages/php/SBOM/coolify/cdxgen/coolify_cdxgen_sbom.json`
  - `languages/php/SBOM/coolify/syft/coolify_syft_sbom.json`
  - `languages/php/SBOM/coolify/trivy/coolify_trivy_sbom.json`
- 출력(예: `code/analyze/out/php-js-gt-coolify/validation/`)
  - `summary.json`: SBOM별 TP/FP/FN 및 지표 요약
  - `<sbom_stem>.tp.csv|fp.csv|fn.csv`: 도구별 TP/FP/FN 목록

```powershell
python code/analyze/php_js_sbom_gt_validate.py \
  --gt-dir code/analyze/out/php-js-gt-coolify \
  --sbom languages/php/SBOM/coolify/cdxgen/coolify_cdxgen_sbom.json \
  --sbom languages/php/SBOM/coolify/syft/coolify_syft_sbom.json \
  --sbom languages/php/SBOM/coolify/trivy/coolify_trivy_sbom.json \
  --out-dir code/analyze/out/php-js-gt-coolify/validation
```

### 이번 실행 결과 요약(coolify)

- GT expected deps: 407
- cdxgen: TP=407 FP=0 FN=0 (precision=1.000, recall=1.000, F1=1.000, accuracy_union=1.000)
- syft: TP=212 FP=1 FN=195 (precision=0.995, recall=0.521, F1=0.684, accuracy_union=0.520)
- trivy: TP=212 FP=0 FN=195 (precision=1.000, recall=0.521, F1=0.685, accuracy_union=0.521)

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
