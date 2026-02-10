# Projects-s-SBOM-Results

특정 언어 별로 star가 많고 유명한 프로젝트에 대한 SBOM 출력/분석 결과를 저장한 레포지토리 입니다.

```text
languages/
├─ cpp/
│  ├─ project/
│  │  └─ # 원본 소스(직접 clone)
│  └─ SBOM/
│     ├─ godot/
│     └─ tesseract/
│        ├─ cdxgen/
│        ├─ hatbom/
│        ├─ syft/
│        └─ trivy/
├─ go/
│  ├─ project/
│  │  └─ # 원본 소스(직접 clone)
│  └─ SBOM/
│     ├─ hugo/
│     └─ terraform/
│        ├─ cdxgen/
│        ├─ hatbom/
│        ├─ syft/
│        └─ trivy/
├─ java/
│  ├─ project/
│  │  ├─ # 원본 소스(직접 clone)
│  └─ SBOM/
│     ├─ dbeaver/
│     ├─ java-spring/
│     └─ javdx/
│
├─ javascript/
│  ├─ project/
│  │  └─ express/…
│  └─ SBOM/
│     └─ express/
│
├─ php/
│  ├─ project/
│  │  ├─ coolify/…
│  │  └─ laravel/…
│  └─ SBOM/
│     ├─ coolify/
│     └─ laravel/
│
├─ python/
│  ├─ project/
│  │  └─ # 원본 소스(직접 clone)
│  └─ SBOM/
│     └─ transformers/
│
├─ ruby/
│  ├─ project/
│  │  └─ rails/…
│  └─ SBOM/
│     └─ rails/
│
└─ typescript/
   ├─ project/
   │  └─ vscode/…
   └─ SBOM/
      └─ vscode/
```

## Directories

- code/: SBOM scheme 및 최소 필드 만족 여부 등을 확인하는 분석 코드
  - code/analyze/: 파서/스키마/식별자(purl) 관련 모듈 및 검증 스크립트
  - code/analyze/out/: 분석 결과 산출물 저장
    - 예) go-gt-terraform/: go.mod 기반 ground truth(JSON/CSV) 및 SBOM 검증 결과(summary.json, 도구별 TP/FP/FN CSV)
  - code/wrapper/: 실행 시간 측정 등 보조 스크립트
- languages/: 언어별 폴더 (cpp, go, java, javascript, php, python, ruby, typescript)
  - languages/<lang>/project/: 해당 언어의 원본 소스 코드(직접 clone)
  - languages/<lang>/SBOM/: 도구별 SBOM 산출물 모음
    - 프로젝트명 예시: terraform, tesseract, express, rails, vscode 등
    - 생성 도구별 하위 폴더: cdxgen/, hatbom/, syft/, trivy/

## Test issues

- cdxgen 사용 이슈: Go 프로젝트에서 docker로 cdxgen 실행 시 권한 에러가 발생하여, npm/go/cdxgen을 로컬에 직접 설치하여 SBOM을 추출한 케이스가 있음. (hugo)
  - 모든 Go 프로젝트에서 이슈가 생긴 것은 아님. (Terraform은 잘 실행되었음.)
