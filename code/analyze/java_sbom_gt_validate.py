#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate Java Maven SBOM outputs against a GT set.

This is the Java/Maven analogue of go_sbom_gt_validate.py.

- GT: a set of Maven coordinates (groupId, artifactId, version)
- Observed: components parsed from CycloneDX SBOM
- Metrics: TP/FP/FN, precision/recall/F1, accuracy_union (Jaccard-style)

Supported SBOM input
- CycloneDX JSON with components[].purl (preferred)
- Fallback: components[].group + components[].name + components[].version

Usage (DBeaver example)
  python code/analyze/java_sbom_gt_validate.py \
    --gt code/analyze/out/java-gt-dbeaver/expected_maven_external.csv \
    --sbom languages/java/SBOM/dbeaver/trivy/dbeaver_trivy_sbom.json \
    --sbom languages/java/SBOM/dbeaver/syft/dbeaver_syft_sbom.json \
    --out-dir code/analyze/out/java-gt-dbeaver/validation
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
class MavenKey:
    group: str  # normalized (lower)
    artifact: str  # normalized (lower)
    version: str  # exact

    def to_purl(self) -> str:
        return f"pkg:maven/{self.group}/{self.artifact}@{self.version}"


def _norm(s: str) -> str:
    return s.strip().lower()


def _strip_qualifiers_and_fragment(purl: str) -> str:
    base = purl.split("?", 1)[0]
    base = base.split("#", 1)[0]
    return base


def parse_maven_purl(purl: str) -> Optional[MavenKey]:
    if not isinstance(purl, str):
        return None
    purl = purl.strip()
    if not purl.startswith("pkg:maven/"):
        return None

    body = _strip_qualifiers_and_fragment(purl[len("pkg:maven/") :])
    if "@" not in body:
        return None

    path_part, version = body.split("@", 1)
    version = unquote(version).strip()
    if not version or version.upper() == "UNKNOWN":
        return None

    segments = [s for s in path_part.split("/") if s]
    if len(segments) < 2:
        return None

    group = "/".join(segments[:-1])
    artifact = segments[-1]

    group_n = _norm(group)
    artifact_n = _norm(artifact)
    if not group_n or not artifact_n:
        return None

    return MavenKey(group=group_n, artifact=artifact_n, version=version)


def _load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def iter_cyclonedx_components(sbom: Dict) -> Iterable[Dict]:
    comps = sbom.get("components")
    if isinstance(comps, list):
        for c in comps:
            if isinstance(c, dict):
                yield c


def load_gt_set(gt_path: Path) -> Set[MavenKey]:
    if gt_path.suffix.lower() == ".json":
        doc = _load_json(gt_path)
        expected = doc.get("expected") or []
        out: Set[MavenKey] = set()
        for e in expected:
            if not isinstance(e, dict):
                continue
            g = e.get("group") or e.get("groupId")
            a = e.get("artifact") or e.get("artifactId")
            v = e.get("version")
            if isinstance(g, str) and isinstance(a, str) and isinstance(v, str) and v.strip() and v.upper() != "UNKNOWN":
                out.add(MavenKey(group=_norm(g), artifact=_norm(a), version=v.strip()))
        return out

    # CSV
    out: Set[MavenKey] = set()
    with gt_path.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            g = row.get("groupId") or row.get("group")
            a = row.get("artifactId") or row.get("artifact")
            v = row.get("version")
            if not g or not a or not v:
                continue
            v = v.strip()
            if not v or v.upper() == "UNKNOWN":
                continue
            out.add(MavenKey(group=_norm(g), artifact=_norm(a), version=v))
    return out


def load_observed_set_from_cyclonedx(sbom_path: Path) -> Set[MavenKey]:
    sbom = _load_json(sbom_path)
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError(f"Unsupported SBOM format in {sbom_path}")

    observed: Set[MavenKey] = set()

    for c in iter_cyclonedx_components(sbom):
        purl = c.get("purl")
        if isinstance(purl, str) and purl.strip():
            key = parse_maven_purl(purl)
            if key is not None:
                observed.add(key)
            # If a purl exists but is not Maven (e.g., pkg:github/...),
            # do NOT fallback to (group,name,version). That would incorrectly
            # reinterpret non-Maven ecosystems as Maven coordinates.
            continue

        # Fallback: group + name + version
        group = c.get("group")
        name = c.get("name")
        version = c.get("version")
        if isinstance(group, str) and isinstance(name, str) and isinstance(version, str):
            v = version.strip()
            if v and v.upper() != "UNKNOWN":
                observed.add(MavenKey(group=_norm(group), artifact=_norm(name), version=v))

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


def compute_metrics(expected: Set[MavenKey], observed: Set[MavenKey]) -> Tuple[Set[MavenKey], Set[MavenKey], Set[MavenKey], Metrics]:
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


def _write_set_csv(path: Path, rows: Sequence[MavenKey]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["groupId", "artifactId", "version", "purl"])
        for r in sorted(rows, key=lambda x: (x.group, x.artifact, x.version)):
            w.writerow([r.group, r.artifact, r.version, r.to_purl()])


def validate_one(expected: Set[MavenKey], sbom_path: Path, out_dir: Path) -> Dict:
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
    ap = argparse.ArgumentParser(description="Validate Maven CycloneDX SBOMs against a GT set")
    ap.add_argument("--gt", type=Path, required=True, help="GT file (.csv or .json from java_trivy_gt_extract.py)")
    ap.add_argument("--sbom", type=Path, action="append", required=True, help="SBOM JSON file (CycloneDX)")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    args = ap.parse_args()

    expected = load_gt_set(args.gt)

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict] = []
    for sbom_path in args.sbom:
        results.append(validate_one(expected, sbom_path, out_dir))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "gt": args.gt.as_posix(),
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
