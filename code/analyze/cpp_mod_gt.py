#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C/C++ dependency ground-truth extractor.

Scans a project tree for declarative build-system signals and exports a
reproducible GT set for SBOM validation.

Primary signals:
- CMake: find_package(), pkg_check_modules(), find_library()
- Autotools: AC_INIT(), PKG_CHECK_MODULES(), AC_CHECK_LIB(), AC_SEARCH_LIBS()

Outputs:
- cpp_mod_gt.json
- cpp_declared_deps.csv
- cpp_internal_targets.csv

Usage (wxWidgets example):
  python code/analyze/cpp_mod_gt.py \
    --root languages/cpp/project/wxWidgets \
    --out-dir code/analyze/out/cpp-gt-wxwidgets
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


_CMAKE_KEYWORDS = {
    "required",
    "quiet",
    "exact",
    "components",
    "optional_components",
    "names",
    "config",
    "module",
    "global",
    "private",
    "public",
    "interface",
    "hints",
    "path_suffixes",
    "default_msg",
}

_PKGCFG_SKIP = {
    "quiet",
    "required",
    "imported_target",
    "global",
    "no_cmake_path",
    "no_cmake_environment_path",
}


@dataclass(frozen=True)
class DeclaredDep:
    name: str
    version: str
    source_kind: str
    file: str
    line: int
    raw: str


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _norm_name(name: str) -> str:
    n = name.strip().strip("\"'[]")
    n = re.sub(r"\s+", "", n)
    return n.lower()


def _looks_variable(token: str) -> bool:
    return "${" in token or "$<" in token


def _tokenize_args(s: str) -> List[str]:
    tokens = re.findall(r'"[^"\\]*(?:\\.[^"\\]*)*"|\[[^\]]*\]|[^\s()]+', s, flags=re.S)
    out: List[str] = []
    for t in tokens:
        t = t.strip()
        if not t:
            continue
        if t.startswith('"') and t.endswith('"') and len(t) >= 2:
            t = t[1:-1]
        out.append(t)
    return out


def _iter_candidate_files(root: Path) -> Iterable[Path]:
    exts = {".cmake", ".m4"}
    names = {"CMakeLists.txt", "configure.ac", "Makefile.am"}
    skip_dirs = {
        ".git",
        "docs",
        "doc",
        "3rdparty",
        "third_party",
        "third-party",
        "build/aclocal",
    }

    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue

        rel = p.relative_to(root).as_posix()
        if any(rel == d or rel.startswith(d + "/") for d in skip_dirs):
            continue

        if p.name in names or p.suffix in exts:
            yield p


def _remove_cmake_comments(line: str) -> str:
    # CMake comments start with # (simple best-effort, ignores quoted # edge cases)
    if "#" in line:
        return line.split("#", 1)[0]
    return line


def _iter_cmake_calls(path: Path) -> Iterable[Tuple[str, int]]:
    lines = _load_text(path).splitlines()
    buf = ""
    depth = 0
    start_line = 1
    active = False

    for idx, raw in enumerate(lines, start=1):
        line = _remove_cmake_comments(raw).strip()
        if not line:
            continue

        if not active:
            if "(" not in line:
                continue
            active = True
            start_line = idx
            buf = line
            depth = line.count("(") - line.count(")")
        else:
            buf += " " + line
            depth += line.count("(") - line.count(")")

        if active and depth <= 0:
            yield buf.strip(), start_line
            buf = ""
            depth = 0
            active = False


def _parse_cmake_project(stmt: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"(?is)^\s*project\s*\((.*)\)\s*$", stmt)
    if not m:
        return None
    toks = _tokenize_args(m.group(1))
    if not toks:
        return None
    name = toks[0]
    version = ""
    for i, t in enumerate(toks):
        if t.lower() == "version" and i + 1 < len(toks):
            version = toks[i + 1].strip()
            break
    if _looks_variable(name):
        return None
    return name, version


def _parse_cmake_targets(stmt: str) -> List[str]:
    out: List[str] = []
    for macro in ("add_library", "add_executable"):
        m = re.match(rf"(?is)^\s*{macro}\s*\((.*)\)\s*$", stmt)
        if not m:
            continue
        toks = _tokenize_args(m.group(1))
        if not toks:
            continue
        name = toks[0]
        if _looks_variable(name):
            continue
        out.append(name)
    return out


def _parse_find_package(stmt: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"(?is)^\s*find_package\s*\((.*)\)\s*$", stmt)
    if not m:
        return None
    toks = _tokenize_args(m.group(1))
    if not toks:
        return None
    name = toks[0]
    if _looks_variable(name):
        return None

    version = ""
    if len(toks) >= 2:
        t = toks[1]
        if t.lower() not in _CMAKE_KEYWORDS and re.match(r"^[0-9][A-Za-z0-9._-]*$", t):
            version = t
    return name, version


def _parse_pkg_check_modules(stmt: str) -> List[Tuple[str, str]]:
    m = re.match(r"(?is)^\s*pkg_check_modules\s*\((.*)\)\s*$", stmt)
    if not m:
        return []
    toks = _tokenize_args(m.group(1))
    if len(toks) < 2:
        return []

    # first token is output variable; remaining are pkg specs and options
    out: List[Tuple[str, str]] = []
    for t in toks[1:]:
        low = t.lower()
        if low in _PKGCFG_SKIP or _looks_variable(t):
            continue
        if low in _CMAKE_KEYWORDS:
            continue
        if re.match(r"^(>=|<=|=|>|<)$", t):
            continue

        spec = t.strip().strip("[]")
        if not spec:
            continue

        # spec can contain "pkg>=1.2" or "pkg-1.0"; parse conservative.
        mm = re.match(r"^([A-Za-z0-9+_.-]+?)(?:\s*(?:>=|<=|=|>|<)\s*([A-Za-z0-9+_.-]+))?$", spec)
        if mm:
            out.append((mm.group(1), mm.group(2) or ""))
    return out


def _parse_find_library(stmt: str) -> List[str]:
    m = re.match(r"(?is)^\s*find_library\s*\((.*)\)\s*$", stmt)
    if not m:
        return []
    toks = _tokenize_args(m.group(1))
    if len(toks) < 2:
        return []

    names: List[str] = []
    low_toks = [t.lower() for t in toks]
    if "names" in low_toks:
        i = low_toks.index("names") + 1
        while i < len(toks):
            if low_toks[i] in _CMAKE_KEYWORDS or low_toks[i] in {"hints", "paths", "path_suffixes"}:
                break
            if not _looks_variable(toks[i]):
                names.append(toks[i])
            i += 1
    else:
        # find_library(VAR candidate)
        cand = toks[1]
        if not _looks_variable(cand):
            names.append(cand)
    return names


def parse_cmake_file(path: Path) -> Tuple[List[DeclaredDep], Set[str], List[Dict[str, str]]]:
    deps: List[DeclaredDep] = []
    internal_targets: Set[str] = set()
    projects: List[Dict[str, str]] = []
    f = path.as_posix()

    for stmt, line_no in _iter_cmake_calls(path):
        p = _parse_cmake_project(stmt)
        if p:
            projects.append({"name": p[0], "version": p[1], "file": f, "line": str(line_no), "kind": "cmake"})
            internal_targets.add(_norm_name(p[0]))
            continue

        for t in _parse_cmake_targets(stmt):
            internal_targets.add(_norm_name(t))

        fp = _parse_find_package(stmt)
        if fp:
            deps.append(
                DeclaredDep(
                    name=_norm_name(fp[0]),
                    version=fp[1].strip(),
                    source_kind="cmake:find_package",
                    file=f,
                    line=line_no,
                    raw=stmt,
                )
            )

        for name, ver in _parse_pkg_check_modules(stmt):
            deps.append(
                DeclaredDep(
                    name=_norm_name(name),
                    version=ver.strip(),
                    source_kind="cmake:pkg_check_modules",
                    file=f,
                    line=line_no,
                    raw=stmt,
                )
            )

        for name in _parse_find_library(stmt):
            deps.append(
                DeclaredDep(
                    name=_norm_name(name),
                    version="",
                    source_kind="cmake:find_library",
                    file=f,
                    line=line_no,
                    raw=stmt,
                )
            )

    return deps, internal_targets, projects


def parse_autotools_file(path: Path) -> Tuple[List[DeclaredDep], Set[str], List[Dict[str, str]]]:
    text = _load_text(path)
    f = path.as_posix()
    deps: List[DeclaredDep] = []
    internal_targets: Set[str] = set()
    projects: List[Dict[str, str]] = []

    # AC_INIT([name], [version], ...)
    for m in re.finditer(
        r"AC_INIT\s*\(\s*\[([^\]]+)\]\s*,\s*\[([^\]]+)\]",
        text,
        flags=re.I,
    ):
        name = m.group(1).strip()
        version = m.group(2).strip()
        line_no = text.count("\n", 0, m.start()) + 1
        projects.append({"name": name, "version": version, "file": f, "line": str(line_no), "kind": "autoconf"})
        internal_targets.add(_norm_name(name))

    # PKG_CHECK_MODULES(VAR, [pkg1 >= 1.0 pkg2], ...)
    for m in re.finditer(
        r"PKG_CHECK_MODULES\s*\(\s*\[?[^,\)]+\]?\s*,\s*\[([^\]]+)\]",
        text,
        flags=re.I | re.S,
    ):
        body = m.group(1)
        line_no = text.count("\n", 0, m.start()) + 1
        for spec in re.split(r"\s+", body.strip()):
            spec = spec.strip()
            if not spec:
                continue
            mm = re.match(r"^([A-Za-z0-9+_.-]+?)(?:\s*(?:>=|<=|=|>|<)\s*([A-Za-z0-9+_.-]+))?$", spec)
            if not mm:
                continue
            name = mm.group(1)
            if name in {">=", "<=", "=", ">", "<"}:
                continue
            deps.append(
                DeclaredDep(
                    name=_norm_name(name),
                    version=(mm.group(2) or "").strip(),
                    source_kind="autoconf:pkg_check_modules",
                    file=f,
                    line=line_no,
                    raw=f"PKG_CHECK_MODULES(..., [{body}], ...)",
                )
            )

    # AC_CHECK_LIB(libname, function, ...)
    for m in re.finditer(r"AC_CHECK_LIB\s*\(\s*\[?([A-Za-z0-9+_.-]+)\]?\s*,", text, flags=re.I):
        lib = m.group(1).strip()
        if not lib:
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        deps.append(
            DeclaredDep(
                name=_norm_name(lib),
                version="",
                source_kind="autoconf:ac_check_lib",
                file=f,
                line=line_no,
                raw=m.group(0),
            )
        )

    # AC_SEARCH_LIBS(func, [lib1 lib2], ...)
    for m in re.finditer(r"AC_SEARCH_LIBS\s*\(\s*[^,]+,\s*\[([^\]]+)\]", text, flags=re.I | re.S):
        libs = m.group(1)
        line_no = text.count("\n", 0, m.start()) + 1
        for lib in re.split(r"\s+", libs.strip()):
            lib = lib.strip()
            if not lib:
                continue
            deps.append(
                DeclaredDep(
                    name=_norm_name(lib),
                    version="",
                    source_kind="autoconf:ac_search_libs",
                    file=f,
                    line=line_no,
                    raw=f"AC_SEARCH_LIBS(..., [{libs}], ...)",
                )
            )

    return deps, internal_targets, projects


def _dedupe_deps(items: Sequence[DeclaredDep]) -> List[DeclaredDep]:
    seen: Set[Tuple[str, str, str]] = set()
    out: List[DeclaredDep] = []
    for d in items:
        k = (d.name, d.version, d.source_kind)
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_deps_csv(path: Path, rows: Sequence[DeclaredDep]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name", "version", "source_kind", "file", "line", "raw"])
        for r in sorted(rows, key=lambda x: (x.name, x.version, x.source_kind, x.file, x.line)):
            w.writerow([r.name, r.version, r.source_kind, r.file, r.line, r.raw])


def _write_internal_csv(path: Path, rows: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name"])
        for r in sorted(set(rows)):
            w.writerow([r])


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract C/C++ GT dependencies from CMake/Autotools declarations")
    ap.add_argument("--root", type=Path, required=True, help="Project root to scan")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    args = ap.parse_args()

    root: Path = args.root
    out_dir: Path = args.out_dir

    all_deps: List[DeclaredDep] = []
    internal_targets: Set[str] = set()
    projects: List[Dict[str, str]] = []
    scanned_files: List[str] = []

    for p in _iter_candidate_files(root):
        scanned_files.append(p.as_posix())
        low_name = p.name.lower()
        if low_name == "cmakelists.txt" or p.suffix.lower() == ".cmake":
            deps, internal, projs = parse_cmake_file(p)
        elif low_name == "configure.ac" or p.suffix.lower() == ".m4" or low_name == "makefile.am":
            deps, internal, projs = parse_autotools_file(p)
        else:
            deps, internal, projs = [], set(), []
        all_deps.extend(deps)
        internal_targets.update(internal)
        projects.extend(projs)

    deps = _dedupe_deps(all_deps)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": root.as_posix(),
        "scanned_files": scanned_files,
        "project_identities": projects,
        "internal_targets": sorted(internal_targets),
        "dependencies": [asdict(d) for d in deps],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(out_dir / "cpp_mod_gt.json", payload)
    _write_deps_csv(out_dir / "cpp_declared_deps.csv", deps)
    _write_internal_csv(out_dir / "cpp_internal_targets.csv", sorted(internal_targets))

    by_kind: Dict[str, int] = {}
    for d in deps:
        by_kind[d.source_kind] = by_kind.get(d.source_kind, 0) + 1

    print(f"Scanned manifest files: {len(scanned_files)}")
    print(f"Declared deps (dedup): {len(deps)}")
    print("By source kind:")
    for k in sorted(by_kind.keys()):
        print(f"  - {k}: {by_kind[k]}")
    print(f"Internal targets: {len(internal_targets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
