#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate C/C++ CycloneDX SBOMs against declaration-based GT.

Compares SBOM component names to GT dependency names extracted by cpp_mod_gt.py.

Metrics:
- TP / FP / FN
- precision, recall, F1
- accuracy_union = TP / |GT union SBOM|

Usage (wxWidgets example):
  python code/analyze/cpp_sbom_gt_validate.py \
    --gt-dir code/analyze/out/cpp-gt-wxwidgets \
    --sbom languages/cpp/SBOM/wxWidgets/cdxgen/wxWidgets_cdxgen_sbom.json \
    --sbom languages/cpp/SBOM/wxWidgets/syft/wxWidgets_syft_sbom.json \
    --sbom languages/cpp/SBOM/wxWidgets/trivy/wxWidgets_trivy_sbom.json \
    --out-dir code/analyze/out/cpp-gt-wxwidgets/validation
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


def _load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _norm_name(name: str) -> str:
    n = name.strip().strip("\"'[]")
    n = re.sub(r"\s+", "", n)
    return n.lower()


@dataclass(frozen=True)
class DepKey:
    name: str


def _purl_name_and_version(purl: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not isinstance(purl, str):
        return None, None, None
    s = purl.strip()
    if not s.startswith("pkg:"):
        return None, None, None

    # drop qualifiers/fragments
    for sep in ("?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]

    body = s[len("pkg:") :]
    if "/" not in body:
        return None, None, None
    ptype, rest = body.split("/", 1)
    ptype = ptype.strip().lower()

    version = None
    if "@" in rest:
        name_part, ver = rest.split("@", 1)
        version = unquote(ver.strip())
    else:
        name_part = rest

    # purl name may contain namespace segments; keep last segment for generic matching
    name_part = unquote(name_part.strip())
    if not name_part:
        return None, None, None

    if "/" in name_part:
        name_simple = name_part.rsplit("/", 1)[1]
    else:
        name_simple = name_part

    return _norm_name(name_simple), (version or ""), ptype


def iter_cyclonedx_components(sbom: Dict) -> Iterable[Dict]:
    comps = sbom.get("components")
    if isinstance(comps, list):
        for c in comps:
            if isinstance(c, dict):
                yield c


def _read_sbom_root_name(sbom: Dict) -> Optional[str]:
    md = sbom.get("metadata")
    if not isinstance(md, dict):
        return None
    comp = md.get("component")
    if not isinstance(comp, dict):
        return None
    purl = comp.get("purl")
    if isinstance(purl, str):
        n, _v, _t = _purl_name_and_version(purl)
        if n:
            return n
    name = comp.get("name")
    if isinstance(name, str):
        return _norm_name(name)
    return None


def load_observed_set_from_cyclonedx(sbom_path: Path) -> Tuple[Set[DepKey], Dict[str, Set[str]], Optional[str]]:
    sbom = _load_json(sbom_path)
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError(f"Unsupported SBOM format in {sbom_path}")

    observed: Set[DepKey] = set()
    versions_by_name: Dict[str, Set[str]] = {}

    for c in iter_cyclonedx_components(sbom):
        name: Optional[str] = None
        version = ""

        purl = c.get("purl")
        if isinstance(purl, str):
            pn, pv, _ptype = _purl_name_and_version(purl)
            if pn:
                name = pn
                version = pv or ""

        if not name:
            n = c.get("name")
            if isinstance(n, str) and n.strip():
                name = _norm_name(n)
            v = c.get("version")
            if isinstance(v, str):
                version = v.strip()

        if not name:
            continue

        observed.add(DepKey(name=name))
        versions_by_name.setdefault(name, set())
        if version:
            versions_by_name[name].add(version)

    return observed, versions_by_name, _read_sbom_root_name(sbom)


def load_gt_expected_set(gt_dir: Path) -> Tuple[Set[DepKey], Dict[str, Set[str]], Set[str], Set[str]]:
    gt_path = gt_dir / "cpp_mod_gt.json"
    doc = _load_json(gt_path)

    deps = doc.get("dependencies") or []
    internal_targets = {_norm_name(x) for x in (doc.get("internal_targets") or []) if isinstance(x, str)}

    project_names: Set[str] = set()
    for p in doc.get("project_identities") or []:
        if isinstance(p, dict) and isinstance(p.get("name"), str):
            project_names.add(_norm_name(p["name"]))

    expected: Set[DepKey] = set()
    gt_versions_by_name: Dict[str, Set[str]] = {}
    for d in deps:
        if not isinstance(d, dict):
            continue
        name = d.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        n = _norm_name(name)
        if n in project_names:
            continue
        expected.add(DepKey(name=n))

        v = d.get("version")
        if isinstance(v, str) and v.strip():
            gt_versions_by_name.setdefault(n, set()).add(v.strip())

    return expected, gt_versions_by_name, internal_targets, project_names


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


def _versions_to_str(versions: Optional[Set[str]]) -> str:
    if not versions:
        return ""
    return "|".join(sorted(versions))


def _write_set_csv(
    path: Path,
    rows: Sequence[DepKey],
    gt_versions_by_name: Dict[str, Set[str]],
    sbom_versions_by_name: Dict[str, Set[str]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name", "gt_versions", "sbom_versions"])
        for r in sorted(rows, key=lambda x: x.name):
            w.writerow([
                r.name,
                _versions_to_str(gt_versions_by_name.get(r.name)),
                _versions_to_str(sbom_versions_by_name.get(r.name)),
            ])


def _classify_fp(name: str, sbom_root: Optional[str], internal_targets: Set[str], project_names: Set[str]) -> str:
    if sbom_root and name == sbom_root:
        return "root_component"
    if name in internal_targets or name in project_names:
        return "internal_target"
    if name in {"/src", "src", "."}:
        return "root_path_component"
    if name in {"pkgconfig", "cmake", "make", "ninja"}:
        return "build_tooling"
    return "other"


def _write_fp_triage_csv(
    path: Path,
    rows: Sequence[DepKey],
    sbom_root: Optional[str],
    internal_targets: Set[str],
    project_names: Set[str],
) -> Dict[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name", "reason"])
        for r in sorted(rows, key=lambda x: x.name):
            reason = _classify_fp(r.name, sbom_root, internal_targets, project_names)
            counts[reason] = counts.get(reason, 0) + 1
            w.writerow([r.name, reason])
    return counts


def validate_one(
    expected: Set[DepKey],
    gt_versions_by_name: Dict[str, Set[str]],
    sbom_path: Path,
    out_dir: Path,
    internal_targets: Set[str],
    project_names: Set[str],
) -> Dict:
    observed, sbom_versions_by_name, sbom_root = load_observed_set_from_cyclonedx(sbom_path)

    tp_set, fp_set, fn_set, m = compute_metrics(expected, observed)

    stem = sbom_path.stem
    _write_set_csv(out_dir / f"{stem}.tp.csv", list(tp_set), gt_versions_by_name, sbom_versions_by_name)
    _write_set_csv(out_dir / f"{stem}.fp.csv", list(fp_set), gt_versions_by_name, sbom_versions_by_name)
    _write_set_csv(out_dir / f"{stem}.fn.csv", list(fn_set), gt_versions_by_name, sbom_versions_by_name)
    fp_reason_counts = _write_fp_triage_csv(
        out_dir / f"{stem}.fp_triage.csv",
        list(fp_set),
        sbom_root,
        internal_targets,
        project_names,
    )

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
    ap = argparse.ArgumentParser(description="Validate C/C++ CycloneDX SBOMs against declaration GT")
    ap.add_argument("--gt-dir", type=Path, required=True, help="Directory containing cpp_mod_gt.json")
    ap.add_argument("--sbom", type=Path, action="append", required=True, help="CycloneDX SBOM JSON path")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    args = ap.parse_args()

    expected, gt_versions_by_name, internal_targets, project_names = load_gt_expected_set(args.gt_dir)

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict] = []
    for sbom_path in args.sbom:
        results.append(
            validate_one(
                expected,
                gt_versions_by_name,
                sbom_path,
                out_dir,
                internal_targets,
                project_names,
            )
        )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gt_dir": args.gt_dir.as_posix(),
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
