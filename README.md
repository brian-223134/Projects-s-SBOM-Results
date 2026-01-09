# Projects-s-SBOM-Results

특정 언어 별로 star가 많고 유명한 프로젝트에 대한 SBOM 출력/분석 결과를 저장한 레포지토리 입니다.

```text
languages/
├─ cpp/
│  ├─ project/
│  │  └─ godot/…           # 원본 소스
│  └─ SBOM/
│     └─ godot/
│        ├─ cdxgen/
│        ├─ hatbom/
│        ├─ syft/
│        └─ trivy/
├─ go/
│  ├─ project/
│  │  └─ hugo/…            # 원본 소스
│  └─ SBOM/
│     └─ hugo/
│        ├─ cdxgen/
│        ├─ hatbom/
│        ├─ syft/
│        └─ trivy/
├─ java/
│  ├─ project/
│  │  └─ spring-boot/…     # 원본 소스
│  └─ SBOM/
│     └─ java-spring/
│        ├─ cdxgen/
│        ├─ hatbom/
│        ├─ syft/
│        └─ trivy/
└─ python/
   ├─ project/
   │  └─ transformers/…     # 원본 소스
   └─ SBOM/
      └─ transformers/
         ├─ cdxgen/
         ├─ hatbom/
         ├─ syft/
         └─ trivy/
```

<div> <h2>Directories</h2> <ul> <li><strong>languages/</strong>: 언어별로 폴더를 구분 (cpp, go, java, python 등)</li> <li><strong>project/</strong>: 해당 언어별로 직접 clone한 원본 소스 코드 보관</li> <li><strong>SBOM/</strong>: project의 각 프로젝트별 SBOM 결과 정리 <ul> <li>프로젝트명 폴더 예시: godot, hugo, java-spring, transformers</li> <li>SBOM 생성 도구별 하위 폴더: <strong>cdxgen/</strong>, <strong>hatbom/</strong>, <strong>syft/</strong>, <strong>trivy/</strong></li> <li>각 도구 폴더에는 해당 생성기로 추출한 SBOM 산출물(JSON 등)이 들어 있음</li> </ul> </li> </ul> </div>

<div> 
    <h2> TEST ISSUES </h2>
    <ul><li><strong> cdxgen 사용 이슈: </strong> GO 언어로 작성된 프로젝트인 경우 docker에서 cdxgen을 사용했을 때 권한 에러가 발생하여 npm, go, cdxgen을 로컬에 직접 다운로드 하여 SBOM을 추출하였음.
    </li></ul>
</div>
