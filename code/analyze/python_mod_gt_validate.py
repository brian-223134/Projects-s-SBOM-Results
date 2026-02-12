#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate Python SBOM outputs against lockfile-derived ground truth.

Compares SBOM component sets (pkg:pypi purls or name+version pairs)
to a GT set extracted by python_mod_gt.py.

Metrics:
- True Positives (TP), False Positives (FP), False Negatives (FN)
- precision, recall, F1
- accuracy_union = TP / |GT ∪ SBOM| (Jaccard-style "accuracy")

Supported SBOM input:
- CycloneDX JSON with components[].purl (cdxgen, trivy, syft)

Usage (LangChain example):
  python python_mod_gt_validate.py \
    --gt-dir code/analyze/out/python-gt-langchain \
    --sbom languages/python/SBOM/langchain/cdxgen/langchain_cdxgen_sbom.json \
    --sbom languages/python/SBOM/langchain/syft/langchain_syft_sbom.json \
    --sbom languages/python/SBOM/langchain/trivy/langchain_trivy_sbom.json \
    --out-dir code/analyze/out/python-gt-langchain/validation
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote


_PEP503_RE = re.compile(r"[-_.]+")


def _pep503_normalize(name: str) -> str:
    return _PEP503_RE.sub("-", name.strip().lower())


@dataclass(frozen=True)
class DepKey:
    name: str
    version: str

    def to_purl(self) -> str:
        return f"pkg:pypi/{self.name}@{self.version}"


def _load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def iter_cyclonedx_components(sbom: Dict) -> Iterable[Dict]:
    comps = sbom.get("components")
    if isinstance(comps, list):
        for c in comps:
            if isinstance(c, dict):
                yield c


def _parse_pypi_purl(purl: str) -> Optional[DepKey]:
    if not isinstance(purl, str):
        return None
    purl = purl.strip()
    if not purl.startswith("pkg:pypi/"):
        return None
    body = purl[len("pkg:pypi/") :]
    if "@" not in body:
        return None
    name, ver = body.split("@", 1)
    name = _pep503_normalize(name)
    ver = unquote(ver).strip()
    if not name or not ver:
        return None
    if ver.upper() == "UNKNOWN" or ver.lower() == "latest":
        return None
    return DepKey(name=name, version=ver)


def _read_sbom_root_component(sbom: Dict) -> Optional[DepKey]:
    md = sbom.get("metadata")
    if not isinstance(md, dict):
        return None
    comp = md.get("component")
    if not isinstance(comp, dict):
        return None
    purl = comp.get("purl")
    if isinstance(purl, str):
        return _parse_pypi_purl(purl)
    name = comp.get("name")
    version = comp.get("version")
    if isinstance(name, str) and isinstance(version, str):
        n = _pep503_normalize(name)
        v = version.strip()
        if n and v and v.upper() != "UNKNOWN" and v.lower() != "latest":
            return DepKey(name=n, version=v)
    return None


def load_observed_set_from_cyclonedx(sbom_path: Path) -> Tuple[Set[DepKey], Optional[DepKey]]:
    sbom = _load_json(sbom_path)
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError(f"Unsupported SBOM format in {sbom_path}")

    root_comp = _read_sbom_root_component(sbom)

    observed: Set[DepKey] = set()
    for c in iter_cyclonedx_components(sbom):
        purl = c.get("purl")
        key = _parse_pypi_purl(purl) if isinstance(purl, str) else None
        if key is not None:
            observed.add(key)
            continue

        # Fallback: (name, version) when purl missing
        name = c.get("name")
        version = c.get("version")
        if isinstance(name, str) and isinstance(version, str):
            n = _pep503_normalize(name)
            v = version.strip()
            if n and v and v.upper() != "UNKNOWN" and v.lower() != "latest":
                observed.add(DepKey(name=n, version=v))

    return observed, root_comp


def load_gt_expected_set(gt_dir: Path, include_non_registry: bool = False) -> Tuple[Set[DepKey], Set[str]]:
    """Load expected dependency set from python_mod_gt.json.

    Returns: (expected_set, internal_names)
    internal_names are package names from non-registry sources (editable/directory/git/url/etc).
    """

    gt_path = gt_dir / "python_mod_gt.json"
    doc = _load_json(gt_path)
    manifests = doc.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError(f"Invalid GT format: {gt_path}")

    expected: Set[DepKey] = set()
    internal_names: Set[str] = set()

    for m in manifests:
        if not isinstance(m, dict):
            continue
        resolved = m.get("resolved")
        if not isinstance(resolved, list):
            continue
        for r in resolved:
            if not isinstance(r, dict):
                continue
            name = r.get("name")
            ver = r.get("version")
            source_kind = r.get("source_kind")
            if not isinstance(name, str) or not isinstance(ver, str):
                continue
            n = _pep503_normalize(name)
            v = ver.strip()
            if not n or not v:
                continue

            if isinstance(source_kind, str) and source_kind != "registry":
                internal_names.add(n)
                if not include_non_registry:
                    continue

            expected.add(DepKey(name=n, version=v))

    return expected, internal_names


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
        w.writerow(["name", "version", "purl"])
        for r in sorted(rows, key=lambda x: (x.name, x.version)):
            w.writerow([r.name, r.version, r.to_purl()])


def _classify_fp(dep: DepKey, sbom_root: Optional[DepKey], internal_names: Set[str]) -> str:
    if sbom_root is not None and dep == sbom_root:
        return "root_component"
    if dep.name in internal_names:
        return "internal_local"
    return "other"


def _write_fp_triage_csv(path: Path, rows: Sequence[DepKey], sbom_root: Optional[DepKey], internal_names: Set[str]) -> Dict[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name", "version", "purl", "reason"])
        for r in sorted(rows, key=lambda x: (x.name, x.version)):
            reason = _classify_fp(r, sbom_root, internal_names)
            counts[reason] = counts.get(reason, 0) + 1
            w.writerow([r.name, r.version, r.to_purl(), reason])
    return counts


def validate_one(expected: Set[DepKey], internal_names: Set[str], sbom_path: Path, out_dir: Path) -> Dict:
    observed, sbom_root = load_observed_set_from_cyclonedx(sbom_path)
    tp_set, fp_set, fn_set, m = compute_metrics(expected, observed)

    stem = sbom_path.stem
    _write_set_csv(out_dir / f"{stem}.tp.csv", list(tp_set))
    _write_set_csv(out_dir / f"{stem}.fp.csv", list(fp_set))
    _write_set_csv(out_dir / f"{stem}.fn.csv", list(fn_set))
    fp_reason_counts = _write_fp_triage_csv(out_dir / f"{stem}.fp_triage.csv", list(fp_set), sbom_root, internal_names)

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
    ap = argparse.ArgumentParser(description="Validate Python SBOMs against lockfile GT")
    ap.add_argument("--gt-dir", type=Path, required=True, help="Directory containing python_mod_gt.json")
    ap.add_argument("--sbom", type=Path, action="append", required=True, help="SBOM JSON file (CycloneDX)")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    ap.add_argument("--include-non-registry", action="store_true", help="Include editable/directory/git/url packages from GT")
    args = ap.parse_args()

    expected, internal_names = load_gt_expected_set(args.gt_dir, include_non_registry=args.include_non_registry)

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict] = []
    for sbom_path in args.sbom:
        results.append(validate_one(expected, internal_names, sbom_path, out_dir))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gt_dir": args.gt_dir.as_posix(),
        "include_non_registry": args.include_non_registry,
        "results": results,
        "metric_definition": {
            "accuracy_union": "TP / |GT union SBOM| (Jaccard-style, since TN is undefined for SBOM comparison)",
            "f1": "2TP / (2TP + FP + FN)",
        },
    }

    (out_dir / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"GT expected deps: {len(expected)}")
    for r in results:
        print(
            f"{Path(r['sbom']).name}: TP={r['tp']} FP={r['fp']} FN={r['fn']} "
            f"P={r['precision']:.3f} R={r['recall']:.3f} F1={r['f1']:.3f} AccU={r['accuracy_union']:.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
