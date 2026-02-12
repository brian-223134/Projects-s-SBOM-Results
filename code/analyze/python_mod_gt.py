#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Python dependency ground-truth extractor.

Scans a directory tree for Python dependency manifests / lockfiles and exports
resolved packages (name, version) for SBOM validation.

Primary targets (resolved, exact versions):
- uv.lock (TOML; used by Astral uv)
- poetry.lock (best-effort TOML)
- pdm.lock (TOML)
- Pipfile.lock (JSON)
- requirements*.txt (only pinned lines like name==version)

Outputs:
- python_mod_gt.json: structured GT
- python_mod_packages.csv: flattened resolved package table
- python_mod_declared.csv: flattened declared (unpinned) requirements table

Usage (LangChain monorepo example):
  python python_mod_gt.py \
    --root languages/python/project/langchain \
    --out-dir code/analyze/out/python-gt-langchain
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


try:
    import tomllib  # py3.11+
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore


_REQ_PIN_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?P<op>==|===)\s*(?P<ver>[^\s;#]+)\s*(?:;[^#]+)?\s*$"
)


def _pep503_normalize(name: str) -> str:
    # PEP 503 normalization: lowercase and replace runs of [-_.] with '-'
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _load_toml(path: Path) -> Dict[str, Any]:
    if tomllib is None:
        raise RuntimeError("tomllib not available (need Python 3.11+)")
    return tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))


@dataclass(frozen=True)
class ResolvedPkg:
    name: str
    version: str
    source_kind: str
    source: str
    file: str


@dataclass(frozen=True)
class DeclaredReq:
    name: str
    specifier: str
    file: str
    line: int
    group: str


@dataclass
class ManifestDoc:
    file: str
    kind: str
    project_name: Optional[str]
    project_version: Optional[str]
    resolved: List[ResolvedPkg]
    declared: List[DeclaredReq]
    notes: List[str]


def iter_candidate_files(root: Path) -> Iterable[Path]:
    names = {
        "uv.lock",
        "poetry.lock",
        "pdm.lock",
        "Pipfile.lock",
        "Pipfile",
        "pyproject.toml",
        "requirements.txt",
        "setup.cfg",
        "setup.py",
    }
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.name in names:
            yield p
            continue
        if p.name.startswith("requirements") and p.suffix == ".txt":
            yield p


def _read_pyproject_name_version(pyproject_path: Path) -> Tuple[Optional[str], Optional[str]]:
    try:
        doc = _load_toml(pyproject_path)
    except Exception:
        return None, None

    project = doc.get("project")
    if isinstance(project, dict):
        name = project.get("name")
        version = project.get("version")
        return (str(name) if isinstance(name, str) else None, str(version) if isinstance(version, str) else None)

    tool = doc.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            name = poetry.get("name")
            version = poetry.get("version")
            return (str(name) if isinstance(name, str) else None, str(version) if isinstance(version, str) else None)

    return None, None


def parse_uv_lock(path: Path) -> Tuple[List[ResolvedPkg], List[str]]:
    doc = _load_toml(path)
    pkgs = doc.get("package")
    if not isinstance(pkgs, list):
        return [], ["uv.lock missing 'package' array"]

    out: List[ResolvedPkg] = []
    notes: List[str] = []
    for p in pkgs:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        ver = p.get("version")
        if not isinstance(name, str) or not isinstance(ver, str):
            continue

        name_norm = _pep503_normalize(name)
        ver = ver.strip()
        if not name_norm or not ver:
            continue

        source_kind = "unknown"
        source_val = ""
        source = p.get("source")
        if isinstance(source, dict):
            if "registry" in source and isinstance(source.get("registry"), str):
                source_kind = "registry"
                source_val = str(source.get("registry"))
            elif "editable" in source and isinstance(source.get("editable"), str):
                source_kind = "editable"
                source_val = str(source.get("editable"))
            elif "directory" in source and isinstance(source.get("directory"), str):
                source_kind = "directory"
                source_val = str(source.get("directory"))
            elif "git" in source and isinstance(source.get("git"), str):
                source_kind = "git"
                source_val = str(source.get("git"))
            elif "url" in source and isinstance(source.get("url"), str):
                source_kind = "url"
                source_val = str(source.get("url"))
            else:
                source_kind = "other"
                source_val = json.dumps(source, ensure_ascii=False)

        out.append(
            ResolvedPkg(
                name=name_norm,
                version=ver,
                source_kind=source_kind,
                source=source_val,
                file=path.as_posix(),
            )
        )

    return out, notes


def parse_pipfile_lock(path: Path) -> Tuple[List[ResolvedPkg], List[str]]:
    doc = _load_json(path)
    out: List[ResolvedPkg] = []
    notes: List[str] = []

    for section in ("default", "develop"):
        items = doc.get(section)
        if items is None:
            continue
        if not isinstance(items, dict):
            continue
        for name, meta in items.items():
            if not isinstance(name, str):
                continue
            version = ""
            if isinstance(meta, dict):
                v = meta.get("version")
                if isinstance(v, str):
                    version = v
            # Pipfile.lock version is like "==1.2.3"
            version = version.strip()
            if version.startswith("=="):
                version = version[2:]
            if not version:
                continue
            out.append(
                ResolvedPkg(
                    name=_pep503_normalize(name),
                    version=version,
                    source_kind="pipfile_lock",
                    source=section,
                    file=path.as_posix(),
                )
            )

    return out, notes


def parse_requirements_txt(path: Path) -> Tuple[List[ResolvedPkg], List[DeclaredReq], List[str]]:
    resolved: List[ResolvedPkg] = []
    declared: List[DeclaredReq] = []
    notes: List[str] = []

    for idx, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            # -r, -e, --find-links, etc.
            continue

        m = _REQ_PIN_RE.match(raw)
        if m:
            name = _pep503_normalize(m.group("name"))
            ver = m.group("ver").strip()
            if name and ver:
                resolved.append(
                    ResolvedPkg(
                        name=name,
                        version=ver,
                        source_kind="requirements_pin",
                        source=path.name,
                        file=path.as_posix(),
                    )
                )
            continue

        # Best-effort declared requirement capture (unpinned)
        # Keep the whole token before ';' and comments
        token = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if token:
            # Extract leading name if possible
            lead = re.split(r"[\s\[<>=!~]", token, 1)[0].strip()
            if lead and re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", lead):
                declared.append(
                    DeclaredReq(
                        name=_pep503_normalize(lead),
                        specifier=token.strip(),
                        file=path.as_posix(),
                        line=idx,
                        group="requirements",
                    )
                )

    return resolved, declared, notes


def parse_pyproject_declared(path: Path) -> Tuple[List[DeclaredReq], List[str]]:
    try:
        doc = _load_toml(path)
    except Exception:
        return [], ["failed to parse pyproject.toml"]

    out: List[DeclaredReq] = []
    notes: List[str] = []

    def add_req_list(reqs: Any, group: str) -> None:
        if not isinstance(reqs, list):
            return
        for i, r in enumerate(reqs, start=1):
            if not isinstance(r, str):
                continue
            token = r.split(";", 1)[0].strip()
            if not token:
                continue
            lead = re.split(r"[\s\[<>=!~]", token, 1)[0].strip()
            if lead:
                out.append(
                    DeclaredReq(
                        name=_pep503_normalize(lead),
                        specifier=r.strip(),
                        file=path.as_posix(),
                        line=0,
                        group=group,
                    )
                )

    project = doc.get("project")
    if isinstance(project, dict):
        add_req_list(project.get("dependencies"), "project")

        opt = project.get("optional-dependencies")
        if isinstance(opt, dict):
            for group, reqs in opt.items():
                add_req_list(reqs, f"optional:{group}")

    # PEP 735 dependency-groups
    dep_groups = doc.get("dependency-groups")
    if isinstance(dep_groups, dict):
        for group, reqs in dep_groups.items():
            add_req_list(reqs, f"group:{group}")

    return out, notes


def write_json(out_path: Path, payload: object) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_resolved_csv(out_path: Path, docs: Sequence[ManifestDoc]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["kind", "manifest_file", "project_name", "package", "version", "source_kind", "source"])
        for d in docs:
            for p in d.resolved:
                w.writerow([d.kind, d.file, d.project_name or "", p.name, p.version, p.source_kind, p.source])


def write_declared_csv(out_path: Path, docs: Sequence[ManifestDoc]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["kind", "manifest_file", "project_name", "name", "specifier", "group", "line"])
        for d in docs:
            for r in d.declared:
                w.writerow([d.kind, d.file, d.project_name or "", r.name, r.specifier, r.group, r.line])


def build_docs(root: Path) -> List[ManifestDoc]:
    docs: List[ManifestDoc] = []
    seen: set[str] = set()

    for p in iter_candidate_files(root):
        key = p.as_posix()
        if key in seen:
            continue
        seen.add(key)

        kind = "unknown"
        resolved: List[ResolvedPkg] = []
        declared: List[DeclaredReq] = []
        notes: List[str] = []

        if p.name == "uv.lock":
            kind = "uv.lock"
            resolved, notes = parse_uv_lock(p)
        elif p.name == "Pipfile.lock":
            kind = "Pipfile.lock"
            resolved, notes = parse_pipfile_lock(p)
        elif p.name.endswith(".lock") and p.name in {"poetry.lock", "pdm.lock"}:
            # Best-effort: try TOML and extract a few common shapes.
            kind = p.name
            try:
                doc = _load_toml(p)
                # poetry.lock: [[package]] name/version
                pkgs = doc.get("package")
                if isinstance(pkgs, list):
                    for pkg in pkgs:
                        if not isinstance(pkg, dict):
                            continue
                        name = pkg.get("name")
                        ver = pkg.get("version")
                        if isinstance(name, str) and isinstance(ver, str):
                            resolved.append(
                                ResolvedPkg(
                                    name=_pep503_normalize(name),
                                    version=ver.strip(),
                                    source_kind="lock",
                                    source="registry",
                                    file=p.as_posix(),
                                )
                            )
            except Exception:
                notes.append("failed to parse lock file")
        elif p.suffix == ".txt" and p.name.startswith("requirements"):
            kind = "requirements"
            r, d, n = parse_requirements_txt(p)
            resolved.extend(r)
            declared.extend(d)
            notes.extend(n)
        elif p.name == "pyproject.toml":
            kind = "pyproject.toml"
            d, n = parse_pyproject_declared(p)
            declared.extend(d)
            notes.extend(n)
        else:
            continue

        # Try to associate project name/version from sibling pyproject
        project_name: Optional[str] = None
        project_version: Optional[str] = None
        pyproject = p.parent / "pyproject.toml"
        if pyproject.exists() and pyproject.is_file():
            pn, pv = _read_pyproject_name_version(pyproject)
            project_name = pn
            project_version = pv

        docs.append(
            ManifestDoc(
                file=p.as_posix(),
                kind=kind,
                project_name=project_name,
                project_version=project_version,
                resolved=resolved,
                declared=declared,
                notes=notes,
            )
        )

    return docs


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract Python dependency GT from lockfiles/manifests")
    ap.add_argument("--root", type=Path, required=True, help="Root directory to scan")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    args = ap.parse_args()

    root: Path = args.root
    out_dir: Path = args.out_dir

    docs = build_docs(root)
    generated_at = datetime.now(timezone.utc).isoformat()

    payload = {
        "generated_at": generated_at,
        "root": root.as_posix(),
        "manifests": [
            {
                "file": d.file,
                "kind": d.kind,
                "project_name": d.project_name,
                "project_version": d.project_version,
                "resolved": [asdict(x) for x in d.resolved],
                "declared": [asdict(x) for x in d.declared],
                "notes": d.notes,
            }
            for d in docs
        ],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "python_mod_gt.json", payload)
    write_resolved_csv(out_dir / "python_mod_packages.csv", docs)
    write_declared_csv(out_dir / "python_mod_declared.csv", docs)

    total_resolved = sum(len(d.resolved) for d in docs)
    total_declared = sum(len(d.declared) for d in docs)
    print(f"Manifests found: {len(docs)}")
    print(f"Resolved packages: {total_resolved} | Declared requirements: {total_declared}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
