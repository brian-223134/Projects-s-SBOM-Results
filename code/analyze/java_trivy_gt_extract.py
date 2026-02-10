#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a Maven ground-truth (GT) set for a Java project from a Trivy CycloneDX SBOM.

Motivation
- Java/Tycho(P2/OSGi) projects like DBeaver don't always have a single lockfile-style
  source of truth.
- Trivy SBOM provides a *candidate pool* of observed components.
- We convert those candidates into a reproducible GT by applying explicit filters,
  especially excluding reactor/internal modules discovered by scanning local pom.xml files.

Outputs (in --out-dir)
- gt_candidates_from_trivy.json: all parsed candidates + classification
- internal_modules.json: (groupId, artifactId) pairs observed in local pom.xml files
- expected_maven_all.csv: Maven GT set including internal reactor artifacts
- expected_maven_external.csv: Maven GT set excluding internal reactor artifacts
- filters_report.json: counts by inclusion/exclusion reason

Example (DBeaver)
  python code/analyze/java_trivy_gt_extract.py \
    --project-root languages/java/project/dbeaver \
    --sbom languages/java/SBOM/dbeaver/trivy/dbeaver_trivy_sbom.json \
    --out-dir code/analyze/out/java-gt-dbeaver
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class MavenKey:
    group: str  # normalized (lower)
    artifact: str  # normalized (lower)
    version: str  # exact

    def to_purl(self) -> str:
        return f"pkg:maven/{self.group}/{self.artifact}@{self.version}"


def _load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


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


def iter_cyclonedx_components(sbom: Dict) -> Iterable[Dict]:
    comps = sbom.get("components")
    if isinstance(comps, list):
        for c in comps:
            if isinstance(c, dict):
                yield c


def _tag_local_name(tag: str) -> str:
    # '{ns}artifactId' -> 'artifactId'
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _child_text(elem: ET.Element, child_name: str) -> Optional[str]:
    for child in list(elem):
        if _tag_local_name(child.tag) == child_name:
            if child.text is None:
                return None
            return child.text.strip()
    return None


def _project_coords_from_pom(pom_path: Path) -> Optional[Tuple[str, str]]:
    try:
        root = ET.fromstring(pom_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None

    if _tag_local_name(root.tag) != "project":
        return None

    artifact_id = _child_text(root, "artifactId")
    if not artifact_id:
        return None

    group_id = _child_text(root, "groupId")
    if not group_id:
        parent = None
        for child in list(root):
            if _tag_local_name(child.tag) == "parent":
                parent = child
                break
        if parent is not None:
            group_id = _child_text(parent, "groupId")

    if not group_id:
        return None

    return _norm(group_id), _norm(artifact_id)


def scan_internal_modules_from_poms(project_root: Path) -> Set[Tuple[str, str]]:
    internal: Set[Tuple[str, str]] = set()
    for pom in sorted(project_root.rglob("pom.xml")):
        coords = _project_coords_from_pom(pom)
        if coords is not None:
            internal.add(coords)
    return internal


def is_likely_internal_by_prefix(group: str) -> bool:
    # Fallback heuristic if pom scanning fails / for additional safety.
    return group.startswith("org.jkiss.dbeaver") or group.startswith("com.dbeaver")


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, header: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(list(header))
        for r in rows:
            w.writerow(list(r))


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract Maven GT sets (all/external-only) from Trivy CycloneDX SBOM")
    ap.add_argument("--project-root", type=Path, required=True, help="Java project root (e.g., languages/java/project/dbeaver)")
    ap.add_argument("--sbom", type=Path, required=True, help="Trivy CycloneDX JSON SBOM")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    args = ap.parse_args()

    project_root: Path = args.project_root
    sbom_path: Path = args.sbom
    out_dir: Path = args.out_dir

    sbom = _load_json(sbom_path)
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError(f"Unsupported SBOM format in {sbom_path}")

    internal_modules = scan_internal_modules_from_poms(project_root)

    # Parse candidates
    candidates: List[Dict] = []
    reasons: Dict[str, int] = {}

    expected_all: Set[MavenKey] = set()
    expected_external: Set[MavenKey] = set()

    total_components = 0
    for c in iter_cyclonedx_components(sbom):
        total_components += 1
        purl = c.get("purl")
        key = parse_maven_purl(purl) if isinstance(purl, str) else None

        if key is None:
            reasons["non_maven_or_unparseable"] = reasons.get("non_maven_or_unparseable", 0) + 1
            continue

        group, artifact, version = key.group, key.artifact, key.version

        is_internal = (group, artifact) in internal_modules or is_likely_internal_by_prefix(group)

        record = {
            "groupId": group,
            "artifactId": artifact,
            "version": version,
            "purl": key.to_purl(),
            "source_purl": purl,
            "name": c.get("name"),
            "type": c.get("type"),
            "internal": bool(is_internal),
        }
        candidates.append(record)

        expected_all.add(key)
        if is_internal:
            reasons["internal_module"] = reasons.get("internal_module", 0) + 1
        else:
            expected_external.add(key)

    # Write outputs
    generated_at = datetime.now(timezone.utc).isoformat()

    write_json(
        out_dir / "internal_modules.json",
        {
            "generated_at": generated_at,
            "project_root": project_root.as_posix(),
            "count": len(internal_modules),
            "modules": [{"groupId": g, "artifactId": a} for (g, a) in sorted(internal_modules)],
        },
    )

    write_json(
        out_dir / "gt_candidates_from_trivy.json",
        {
            "generated_at": generated_at,
            "sbom": sbom_path.as_posix(),
            "total_components": total_components,
            "candidates_count": len(candidates),
            "candidates": candidates,
        },
    )

    header = ["groupId", "artifactId", "version", "purl", "source"]

    rows_all = [
        [k.group, k.artifact, k.version, k.to_purl(), "trivy"]
        for k in sorted(expected_all, key=lambda x: (x.group, x.artifact, x.version))
    ]
    rows_external = [
        [k.group, k.artifact, k.version, k.to_purl(), "trivy"]
        for k in sorted(expected_external, key=lambda x: (x.group, x.artifact, x.version))
    ]

    write_csv(out_dir / "expected_maven_all.csv", header=header, rows=rows_all)
    write_csv(out_dir / "expected_maven_external.csv", header=header, rows=rows_external)

    write_json(
        out_dir / "expected_maven_all.json",
        {
            "generated_at": generated_at,
            "project_root": project_root.as_posix(),
            "sbom": sbom_path.as_posix(),
            "mode": "all",
            "expected": [
                asdict(k) | {"purl": k.to_purl()}
                for k in sorted(expected_all, key=lambda x: (x.group, x.artifact, x.version))
            ],
        },
    )

    write_json(
        out_dir / "expected_maven_external.json",
        {
            "generated_at": generated_at,
            "project_root": project_root.as_posix(),
            "sbom": sbom_path.as_posix(),
            "mode": "external-only",
            "expected": [
                asdict(k) | {"purl": k.to_purl()}
                for k in sorted(expected_external, key=lambda x: (x.group, x.artifact, x.version))
            ],
        },
    )

    write_json(
        out_dir / "filters_report.json",
        {
            "generated_at": generated_at,
            "total_components": total_components,
            "maven_candidates": len(candidates),
            "expected_all_count": len(expected_all),
            "expected_external_count": len(expected_external),
            "excluded_reasons": reasons,
            "note": "Tycho projects may appear mostly as internal reactor artifacts in Trivy SBOM; expected_maven_all.* is often the useful GT for 'all components'.",
        },
    )

    print(f"Total components: {total_components}")
    print(f"Maven candidates: {len(candidates)}")
    print(f"Internal modules discovered (pom scan): {len(internal_modules)}")
    print(f"Expected(all) size: {len(expected_all)} | Expected(external) size: {len(expected_external)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
