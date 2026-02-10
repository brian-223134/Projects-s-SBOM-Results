# Go module GT extractor

This script extracts *declared* dependency ground-truth signals from `go.mod` files.

## What it exports

- `go_mod_gt.json`: per-`go.mod` parsed data (module/go version/require/replace/tool)
- `go_mod_requires.csv`: flattened require table (direct vs indirect)
- `go_mod_replaces.csv`: flattened replace table
- `go_mod_tools.csv`: flattened tool dependency table

## Run (Terraform example)

```powershell
C:/Users/김찬중(동계 학부 인턴)/Desktop/Projects-s-SBOM-Results/.venv/Scripts/python.exe code/analyze/go_mod_gt.py `
  --root languages/go/project/terraform `
  --out-dir code/analyze/out/go-gt-terraform
```

## Notes for SBOM/ground-truth

- `require` is split into direct vs indirect via `// indirect`.
- `replace` indicates module boundary rewrites (often maps internal modules to local paths).
- `tool` entries are typically build/dev tooling deps, not runtime deps.
