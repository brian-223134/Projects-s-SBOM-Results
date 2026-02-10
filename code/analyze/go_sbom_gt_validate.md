# Go SBOM vs go.mod GT validator

Validates CycloneDX SBOM outputs (cdxgen/syft/trivy) against a go.mod-derived ground truth (GT).

## Inputs

- GT directory produced by `code/analyze/go_mod_gt.py` (needs `go_mod_gt.json`)
- One or more CycloneDX JSON SBOM files

## Output

In `--out-dir`:
- `summary.json`: per-SBOM metrics (TP/FP/FN/precision/recall/F1/accuracy_union)
- `<sbom>.tp.csv`, `<sbom>.fp.csv`, `<sbom>.fn.csv`: matched/mismatched dependency lists

## Run (Terraform)

```powershell
& "C:/Users/김찬중(동계 학부 인턴)/Desktop/Projects-s-SBOM-Results/.venv/Scripts/python.exe" \
  "code/analyze/go_sbom_gt_validate.py" \
  --gt-dir "code/analyze/out/go-gt-terraform" \
  --sbom "languages/go/SBOM/terraform/cdxgen/terraform_cdxgen_sbom.json" \
  --sbom "languages/go/SBOM/terraform/syft/terraform_syft_sbom.json" \
  --sbom "languages/go/SBOM/terraform/trivy/terraform_trivy_sbom.json" \
  --out-dir "code/analyze/out/go-gt-terraform/validation"
```

## Metric notes

- `accuracy_union` is defined as `TP / |GT ∪ SBOM|` (Jaccard-style), because true negatives (TN) are not well-defined in SBOM set comparisons.
- F1 uses the standard `2TP/(2TP+FP+FN)`.
