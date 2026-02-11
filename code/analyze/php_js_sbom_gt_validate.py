#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate CycloneDX SBOM outputs against PHP/JS lockfile GT.

Mirrors the Go validator (go_sbom_gt_validate.py) but compares:
- Expected set: dependencies from php_js_lock_gt.json
- Observed set: CycloneDX JSON components[].purl for pkg:composer and pkg:npm

Usage (coolify example):
  python code/analyze/php_js_lock_gt.py \
    --root languages/php/project/coolify \
    --out-dir code/analyze/out/php-js-gt-coolify

  python code/analyze/php_js_sbom_gt_validate.py \
    --gt-dir code/analyze/out/php-js-gt-coolify \
    --sbom languages/php/SBOM/coolify/cdxgen/coolify_cdxgen_sbom.json \
    --sbom languages/php/SBOM/coolify/syft/coolify_syft_sbom.json \
    --sbom languages/php/SBOM/coolify/trivy/coolify_trivy_sbom.json \
    --out-dir code/analyze/out/php-js-gt-coolify/validation
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


@dataclass(frozen=True)
class DepKey:
    purl: str  # canonicalized (no qualifiers/fragments)


def _load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _canon_purl(purl: str) -> Optional[str]:
    if not isinstance(purl, str):
        return None
    s = purl.strip()
    if not s.startswith("pkg:"):
        return None

    # Drop qualifiers / fragments if present
    for sep in ("?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]

    # Normalize percent-encoding casing for comparison via decode+re-encode-like behavior.
    # We keep decoded string but DO NOT change semantic parts.
    # For npm scopes, SBOM often uses %40; decoding yields '@'.
    # We keep decoded for canonical compare.
    s = unquote(s)

    return s


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
        if not isinstance(purl, str):
            continue
        canon = _canon_purl(purl)
        if canon is None:
            continue

        # Focus on ecosystems we can build GT for.
        if canon.startswith("pkg:composer/") or canon.startswith("pkg:npm/"):
            observed.add(DepKey(purl=canon))

    return observed


def load_expected_set(gt_dir: Path, exclude_dev: bool = False) -> Set[DepKey]:
    gt_path = gt_dir / "php_js_lock_gt.json"
    doc = _load_json(gt_path)

    expected: Set[DepKey] = set()
    for d in doc.get("dependencies") or []:
        if not isinstance(d, dict):
            continue
        if exclude_dev and bool(d.get("dev")):
            continue
        purl = d.get("purl")
        canon = _canon_purl(purl) if isinstance(purl, str) else None
        if canon is None:
            continue
        expected.add(DepKey(purl=canon))

    return expected


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
        w.writerow(["purl"])
        for r in sorted(rows, key=lambda x: x.purl):
            w.writerow([r.purl])


def validate_one(expected: Set[DepKey], sbom_path: Path, out_dir: Path) -> Dict:
    observed = load_observed_set_from_cyclonedx(sbom_path)

    tp_set, fp_set, fn_set, m = compute_metrics(expected, observed)

    stem = sbom_path.stem
    _write_set_csv(out_dir / f"{stem}.tp.csv", list(tp_set))
    _write_set_csv(out_dir / f"{stem}.fp.csv", list(fp_set))
    _write_set_csv(out_dir / f"{stem}.fn.csv", list(fn_set))

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
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate CycloneDX SBOMs against lockfile GT (composer/npm)")
    ap.add_argument("--gt-dir", type=Path, required=True, help="Directory containing php_js_lock_gt.json")
    ap.add_argument("--sbom", type=Path, action="append", required=True, help="SBOM JSON file (CycloneDX)")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    ap.add_argument("--exclude-dev", action="store_true", help="Exclude dev deps from GT")
    args = ap.parse_args()

    expected = load_expected_set(args.gt_dir, exclude_dev=args.exclude_dev)

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict] = []
    for sbom_path in args.sbom:
        results.append(validate_one(expected, sbom_path, out_dir))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gt_dir": args.gt_dir.as_posix(),
        "exclude_dev": bool(args.exclude_dev),
        "results": results,
        "metric_definition": {
            "accuracy_union": "TP / |GT ∪ SBOM| (Jaccard-style, since TN is undefined for SBOM comparison)",
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
