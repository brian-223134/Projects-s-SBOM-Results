#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate Go SBOM outputs against go.mod-derived ground truth.

This compares SBOM component sets to a go.mod GT set and reports:
- True Positives (TP): in both GT and SBOM
- False Positives (FP): in SBOM but not in GT
- False Negatives (FN): in GT but not in SBOM

It also computes:
- precision, recall, F1
- accuracy_union = TP / |GT ∪ SBOM| (Jaccard-style "accuracy" since TN is undefined)

Supported SBOM input:
- CycloneDX JSON with components[].purl (cdxgen, trivy, syft)

Usage (Terraform example):
  python go_sbom_gt_validate.py \
    --gt-dir code/analyze/out/go-gt-terraform \
    --sbom languages/go/SBOM/terraform/cdxgen/terraform_cdxgen_sbom.json \
    --sbom languages/go/SBOM/terraform/syft/terraform_syft_sbom.json \
    --sbom languages/go/SBOM/terraform/trivy/terraform_trivy_sbom.json \
    --out-dir code/analyze/out/go-gt-terraform/validation
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote


_PLACEHOLDER_INTERNAL_VERSION = "v0.0.0-00010101000000-000000000000"


@dataclass(frozen=True)
class DepKey:
    module: str  # normalized (lower)
    version: str  # exact

    def to_purl(self) -> str:
        # version in SBOM purls may be percent-encoded; for comparison we keep raw version.
        return f"pkg:golang/{self.module}@{self.version}"


def _load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _norm_module(s: str) -> str:
    return s.strip().lower()


def _parse_golang_purl(purl: str) -> Optional[DepKey]:
    # Expect: pkg:golang/<module>@<version>
    if not isinstance(purl, str):
        return None
    purl = purl.strip()
    if not purl.startswith("pkg:golang/"):
        return None

    body = purl[len("pkg:golang/") :]
    if "@" not in body:
        return None
    mod, ver = body.split("@", 1)
    mod = _norm_module(mod)
    ver = unquote(ver)
    if not mod or not ver or ver.upper() == "UNKNOWN":
        return None
    return DepKey(module=mod, version=ver)


def load_gt_expected_set(gt_dir: Path, include_indirect: bool = True) -> Tuple[Set[DepKey], str]:
    """Build expected dependency set from go_mod_gt.json.

    Returns: (expected_set, root_module_name)
    """
    gt_path = gt_dir / "go_mod_gt.json"
    doc = _load_json(gt_path)

    modules: List[Dict] = doc.get("modules") or []
    root_module = ""
    for m in modules:
        if m.get("file", "").endswith("/go.mod") and m.get("module"):
            root_module = str(m["module"])
            break
    root_module_norm = _norm_module(root_module) if root_module else ""

    expected: Set[DepKey] = set()

    for m in modules:
        for r in m.get("requires") or []:
            dep_mod = r.get("module")
            dep_ver = r.get("version")
            indirect = bool(r.get("indirect"))

            if not include_indirect and indirect:
                continue
            if not isinstance(dep_mod, str) or not isinstance(dep_ver, str):
                continue

            dep_mod_norm = _norm_module(dep_mod)
            dep_ver = dep_ver.strip()
            if not dep_mod_norm or not dep_ver:
                continue

            # Exclude go.mod directives accidentally emitted as pseudo-packages
            # (e.g., "godebug winsymlink=0" in some SBOM outputs).
            if dep_mod_norm == "godebug":
                continue

            # Exclude internal self-module references (multi-module repo)
            # Note: use exact match or "root/" prefix only.
            # Do NOT treat "root-foo" as internal (e.g., terraform-plugin-go).
            if root_module_norm and (
                dep_mod_norm == root_module_norm or dep_mod_norm.startswith(root_module_norm + "/")
            ):
                continue

            # Exclude placeholder internal version used with replace
            if dep_ver == _PLACEHOLDER_INTERNAL_VERSION:
                continue

            expected.add(DepKey(module=dep_mod_norm, version=dep_ver))

    return expected, root_module_norm


def _classify_fp(dep: DepKey, root_module_norm: str) -> str:
    if dep.module == "godebug":
        return "directive:godebug"
    if dep.version == _PLACEHOLDER_INTERNAL_VERSION:
        return "placeholder_version"
    if dep.module.startswith("registry.terraform.io/"):
        return "terraform_registry_provider"
    if dep.module.startswith("example.com/"):
        return "example_domain"
    if root_module_norm and (
        dep.module == root_module_norm or dep.module.startswith(root_module_norm + "/")
    ):
        return "internal_module"
    return "other"


def iter_cyclonedx_components(sbom: Dict) -> Iterable[Dict]:
    comps = sbom.get("components")
    if isinstance(comps, list):
        for c in comps:
            if isinstance(c, dict):
                yield c


def load_observed_set_from_cyclonedx(sbom_path: Path) -> Set[DepKey]:
    sbom = _load_json(sbom_path)

    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError(f"Unsupported SBOM format in {sbom_path}")

    observed: Set[DepKey] = set()

    for c in iter_cyclonedx_components(sbom):
        purl = c.get("purl")
        key = _parse_golang_purl(purl) if isinstance(purl, str) else None
        if key is not None:
            observed.add(key)
            continue

        # Fallback: (name, version) for Go modules when purl missing
        name = c.get("name")
        version = c.get("version")
        if isinstance(name, str) and isinstance(version, str):
            name_norm = _norm_module(name)
            v = version.strip()
            if name_norm and v and v.upper() != "UNKNOWN":
                # Heuristic filter: likely go module path
                if "." in name_norm and "/" in name_norm and not name_norm.startswith("./"):
                    observed.add(DepKey(module=name_norm, version=v))

    return observed


@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    accuracy_union: float


def compute_metrics(expected: Set[DepKey], observed: Set[DepKey]) -> Tuple[Set[DepKey], Set[DepKey], Set[DepKey], Metrics]:
    tp_set = expected & observed
    fp_set = observed - expected
    fn_set = expected - observed

    tp = len(tp_set)
    fp = len(fp_set)
    fn = len(fn_set)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    union = len(expected | observed)
    accuracy_union = tp / union if union else 0.0

    return tp_set, fp_set, fn_set, Metrics(tp, fp, fn, precision, recall, f1, accuracy_union)


def _write_set_csv(path: Path, rows: Sequence[DepKey]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["module", "version", "purl"])
        for r in sorted(rows, key=lambda x: (x.module, x.version)):
            w.writerow([r.module, r.version, r.to_purl()])


def _write_fp_triage_csv(path: Path, rows: Sequence[DepKey], root_module_norm: str) -> Dict[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["module", "version", "purl", "reason"])
        for r in sorted(rows, key=lambda x: (x.module, x.version)):
            reason = _classify_fp(r, root_module_norm)
            counts[reason] = counts.get(reason, 0) + 1
            w.writerow([r.module, r.version, r.to_purl(), reason])
    return counts


def validate_one(expected: Set[DepKey], sbom_path: Path, out_dir: Path, root_module_norm: str) -> Dict:
    observed = load_observed_set_from_cyclonedx(sbom_path)

    tp_set, fp_set, fn_set, m = compute_metrics(expected, observed)

    # Output per-file tables
    stem = sbom_path.stem
    _write_set_csv(out_dir / f"{stem}.tp.csv", list(tp_set))
    _write_set_csv(out_dir / f"{stem}.fp.csv", list(fp_set))
    _write_set_csv(out_dir / f"{stem}.fn.csv", list(fn_set))
    fp_reason_counts = _write_fp_triage_csv(out_dir / f"{stem}.fp_triage.csv", list(fp_set), root_module_norm)

    return {
        "sbom": sbom_path.as_posix(),
        "observed_count": len(observed),
        "expected_count": len(expected),
        "tp": m.tp,
        "fp": m.fp,
        "fn": m.fn,
        "precision": m.precision,
        "recall": m.recall,
        "f1": m.f1,
        "accuracy_union": m.accuracy_union,
        "fp_reasons": fp_reason_counts,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate Go SBOMs against go.mod ground truth")
    ap.add_argument("--gt-dir", type=Path, required=True, help="Directory containing go_mod_gt.json")
    ap.add_argument("--sbom", type=Path, action="append", required=True, help="SBOM JSON file (CycloneDX)")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    ap.add_argument("--exclude-indirect", action="store_true", help="Exclude // indirect deps from GT")
    args = ap.parse_args()

    expected, root_module = load_gt_expected_set(args.gt_dir, include_indirect=not args.exclude_indirect)

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict] = []
    for sbom_path in args.sbom:
        results.append(validate_one(expected, sbom_path, out_dir, root_module))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gt_dir": args.gt_dir.as_posix(),
        "root_module": root_module,
        "include_indirect": not args.exclude_indirect,
        "results": results,
        "metric_definition": {
            "accuracy_union": "TP / |GT union SBOM| (Jaccard-style, since TN is undefined for SBOM comparison)",
            "f1": "2TP / (2TP + FP + FN)",
        },
    }

    (out_dir / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # console summary
    print(f"GT expected deps: {len(expected)} (root={root_module})")
    for r in results:
        print(
            f"{Path(r['sbom']).name}: TP={r['tp']} FP={r['fp']} FN={r['fn']} "
            f"P={r['precision']:.3f} R={r['recall']:.3f} F1={r['f1']:.3f} AccU={r['accuracy_union']:.3f}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
