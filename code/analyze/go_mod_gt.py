#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Go module ground-truth extractor.

Scans a directory tree for go.mod files and exports:
- Per-module metadata (module path, go version)
- require dependencies (direct/indirect)
- replace directives
- tool dependencies

Outputs are intended for "declared/resolved" ground-truth inputs to compare SBOM tools.

Usage:
  python go_mod_gt.py --root languages/go/project/terraform --out-dir out/go-gt
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class RequireItem:
    module: str
    version: str
    indirect: bool
    file: str
    line: int


@dataclass(frozen=True)
class ReplaceItem:
    old_module: str
    old_version: Optional[str]
    new_target: str
    new_version: Optional[str]
    file: str
    line: int


@dataclass(frozen=True)
class ToolItem:
    module: str
    version: Optional[str]
    file: str
    line: int


@dataclass
class GoModDoc:
    file: str
    module: Optional[str]
    go_version: Optional[str]
    requires: List[RequireItem]
    replaces: List[ReplaceItem]
    tools: List[ToolItem]


def _strip_comment(line: str) -> Tuple[str, str]:
    """Return (code, comment) split at // if present."""
    if "//" not in line:
        return line, ""
    code, comment = line.split("//", 1)
    return code, comment


def _parse_require_line(code: str, comment: str, file: str, line_no: int) -> Optional[RequireItem]:
    parts = code.split()
    if len(parts) < 2:
        return None
    mod = parts[0]
    ver = parts[1]
    indirect = "indirect" in comment
    return RequireItem(module=mod, version=ver, indirect=indirect, file=file, line=line_no)


def _parse_tool_line(code: str, file: str, line_no: int) -> Optional[ToolItem]:
    parts = code.split()
    if not parts:
        return None
    mod = parts[0]
    ver = parts[1] if len(parts) >= 2 else None
    return ToolItem(module=mod, version=ver, file=file, line=line_no)


def _parse_replace_line(code: str, file: str, line_no: int) -> Optional[ReplaceItem]:
    # Expected forms:
    #   replace old => new
    #   replace old v1.2.3 => new v1.2.4
    if "=>" not in code:
        return None

    left, right = (x.strip() for x in code.split("=>", 1))
    left_parts = left.split()
    right_parts = right.split()

    if not left_parts:
        return None

    old_module = left_parts[0]
    old_version = left_parts[1] if len(left_parts) >= 2 else None

    if not right_parts:
        return None

    new_target = right_parts[0]
    new_version = right_parts[1] if len(right_parts) >= 2 else None

    return ReplaceItem(
        old_module=old_module,
        old_version=old_version,
        new_target=new_target,
        new_version=new_version,
        file=file,
        line=line_no,
    )


def parse_go_mod(path: Path) -> GoModDoc:
    file_str = path.as_posix()
    module: Optional[str] = None
    go_version: Optional[str] = None
    requires: List[RequireItem] = []
    replaces: List[ReplaceItem] = []
    tools: List[ToolItem] = []

    mode: Optional[str] = None  # require|replace|tool block

    for idx, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue

        # Block endings
        if mode and line == ")":
            mode = None
            continue

        # Block starts
        if line.startswith("require ("):
            mode = "require"
            continue
        if line.startswith("replace ("):
            mode = "replace"
            continue
        if line.startswith("tool ("):
            mode = "tool"
            continue

        if mode == "require":
            code, comment = _strip_comment(line)
            code = code.strip()
            if not code:
                continue
            item = _parse_require_line(code, comment, file_str, idx)
            if item:
                requires.append(item)
            continue

        if mode == "replace":
            code, _comment = _strip_comment(line)
            code = code.strip()
            if not code:
                continue
            item = _parse_replace_line(code, file_str, idx)
            if item:
                replaces.append(item)
            continue

        if mode == "tool":
            code, _comment = _strip_comment(line)
            code = code.strip()
            if not code:
                continue
            item = _parse_tool_line(code, file_str, idx)
            if item:
                tools.append(item)
            continue

        # Single-line statements
        if line.startswith("module "):
            module = line.split(None, 1)[1].strip()
            continue

        if line.startswith("go "):
            go_version = line.split(None, 1)[1].strip()
            continue

        if line.startswith("require "):
            rest = line.split(None, 1)[1].strip()
            code, comment = _strip_comment(rest)
            item = _parse_require_line(code.strip(), comment, file_str, idx)
            if item:
                requires.append(item)
            continue

        if line.startswith("replace "):
            rest = line.split(None, 1)[1].strip()
            code, _comment = _strip_comment(rest)
            item = _parse_replace_line(code.strip(), file_str, idx)
            if item:
                replaces.append(item)
            continue

        if line.startswith("tool "):
            rest = line.split(None, 1)[1].strip()
            code, _comment = _strip_comment(rest)
            item = _parse_tool_line(code.strip(), file_str, idx)
            if item:
                tools.append(item)
            continue

    return GoModDoc(
        file=file_str,
        module=module,
        go_version=go_version,
        requires=requires,
        replaces=replaces,
        tools=tools,
    )


def iter_go_mod_files(root: Path) -> Iterable[Path]:
    yield from sorted(root.rglob("go.mod"))


def write_json(out_path: Path, payload: object) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_requires_csv(out_path: Path, docs: List[GoModDoc]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "owner_module",
            "owner_file",
            "dep_module",
            "dep_version",
            "indirect",
            "decl_type",
            "source_line",
        ])
        for d in docs:
            owner_mod = d.module or ""
            for r in d.requires:
                w.writerow([
                    owner_mod,
                    r.file,
                    r.module,
                    r.version,
                    "true" if r.indirect else "false",
                    "indirect" if r.indirect else "direct",
                    r.line,
                ])


def write_replaces_csv(out_path: Path, docs: List[GoModDoc]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "owner_module",
            "owner_file",
            "old_module",
            "old_version",
            "new_target",
            "new_version",
            "new_is_path",
            "source_line",
        ])
        for d in docs:
            owner_mod = d.module or ""
            for r in d.replaces:
                new_is_path = r.new_target.startswith("./") or r.new_target.startswith("../") or ":" in r.new_target or r.new_target.startswith("/")
                w.writerow([
                    owner_mod,
                    r.file,
                    r.old_module,
                    r.old_version or "",
                    r.new_target,
                    r.new_version or "",
                    "true" if new_is_path else "false",
                    r.line,
                ])


def write_tools_csv(out_path: Path, docs: List[GoModDoc]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "owner_module",
            "owner_file",
            "tool_module",
            "tool_version",
            "source_line",
        ])
        for d in docs:
            owner_mod = d.module or ""
            for t in d.tools:
                w.writerow([
                    owner_mod,
                    t.file,
                    t.module,
                    t.version or "",
                    t.line,
                ])


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract ground-truth dependency tables from go.mod files")
    ap.add_argument("--root", type=Path, required=True, help="Root directory to scan (e.g., languages/go/project/terraform)")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    args = ap.parse_args()

    root: Path = args.root
    out_dir: Path = args.out_dir

    go_mod_files = list(iter_go_mod_files(root))
    docs = [parse_go_mod(p) for p in go_mod_files]

    generated_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "generated_at": generated_at,
        "root": root.as_posix(),
        "go_mod_files": [p.as_posix() for p in go_mod_files],
        "modules": [
            {
                "file": d.file,
                "module": d.module,
                "go_version": d.go_version,
                "requires": [asdict(x) for x in d.requires],
                "replaces": [asdict(x) for x in d.replaces],
                "tools": [asdict(x) for x in d.tools],
            }
            for d in docs
        ],
    }

    write_json(out_dir / "go_mod_gt.json", payload)
    write_requires_csv(out_dir / "go_mod_requires.csv", docs)
    write_replaces_csv(out_dir / "go_mod_replaces.csv", docs)
    write_tools_csv(out_dir / "go_mod_tools.csv", docs)

    # Short console summary
    total_requires = sum(len(d.requires) for d in docs)
    total_replaces = sum(len(d.replaces) for d in docs)
    total_tools = sum(len(d.tools) for d in docs)
    print(f"Found go.mod files: {len(docs)}")
    print(f"Require entries: {total_requires} | Replace entries: {total_replaces} | Tool entries: {total_tools}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
