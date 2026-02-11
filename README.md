# Projects-s-SBOM-Results

특정 언어 별로 star가 많고 유명한 프로젝트에 대한 SBOM 출력/분석 결과를 저장한 레포지토리 입니다.

```text
code/
├─ analyze/
│  ├─ README.md
│  ├─ *.py
│  └─ out/
│     └─ go-gt-<project>/     # 다른 언어로 작성된 프로젝트도 동일한 형태의 디렉토리를 가짐
│        └─ validation/
└─ wrapper/

languages/
└─ <lang>/
  ├─ project/
  │  └─ <project>/            # 원본 소스(직접 clone)
  └─ SBOM/
    └─ <project>/
      ├─ cdxgen/
      ├─ hatbom/              # 있는 경우만 존재
      ├─ syft/
      └─ trivy/
```

## Directories

- code/: SBOM scheme 및 최소 필드 만족 여부 등을 확인하는 분석 코드
  - code/analyze/: 파서/스키마/식별자(purl) 관련 모듈 및 검증 스크립트
    - 자세한 사용법/산출물 설명: code/analyze/README.md
  - code/analyze/out/: 분석 결과 산출물 저장
    - 예) go-gt-<project>/: go.mod 기반 ground truth(JSON/CSV) 및 SBOM 검증 결과(summary.json, 도구별 TP/FP/FN CSV)
  - code/wrapper/: 실행 시간 측정 등 보조 스크립트
- languages/: 언어별 폴더 (cpp, go, java, javascript, php, python, ruby, typescript)
  - languages/<lang>/project/: 해당 언어의 원본 소스 코드(직접 clone)
    - 프로젝트별 하위 디렉토리: <project>/
  - languages/<lang>/SBOM/: 도구별 SBOM 산출물 모음
    - 프로젝트별 하위 디렉토리: <project>/
    - 생성 도구별 하위 폴더: cdxgen/, hatbom/, syft/, trivy/

## Test issues

- cdxgen 사용 이슈: 일부 Go 프로젝트에서 docker로 cdxgen 실행 시 권한 에러가 발생하여, npm/go/cdxgen을 로컬에 직접 설치하여 SBOM을 추출한 케이스가 있음.
  - 모든 Go 프로젝트에서 이슈가 생긴 것은 아님. -> hugo 관련 데이터는 모두 파기하였음.
