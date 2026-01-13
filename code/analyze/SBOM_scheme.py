#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Schema summary for a JSON SBOM (CycloneDX etc.) — indices collapsed to [].

What it does
------------
- Traverses a single JSON file top-down.
- Produces a "schema-like" list of unique paths where:
  - Object keys are joined by dots:     metadata.tools.components
  - Array indices are collapsed to []:  components[].hashes[].alg
- Aggregates, per path:
  - Observed types (string/integer/number/boolean/null/object/array)
  - Occurrence count (how many times the path was seen)
  - Optional primitive samples (up to 3)

Path notation examples
----------------------
- components[].name
- components[].hashes[].alg
- metadata.tools.components[].name
- dependencies[].dependsOn[]

Usage
-----
1) Print Markdown table to stdout (default):
   python schema_summary.py /path/to/sbom.json

2) Save as TSV:
   python schema_summary.py /path/to/sbom.json --format tsv --out schema.tsv

3) Save as JSON (machine-friendly):
   python schema_summary.py /path/to/sbom.json --format json --out schema.json

4) Omit primitive samples (only path/types/count):
   python schema_summary.py /path/to/sbom.json --no-samples

Concrete examples (your uploaded files)
---------------------------------------
- Trivy SBOM (Markdown):
  python schema_summary.py /mnt/data/hugo_SBOM_trivy.json

- Syft SBOM (TSV):
  python schema_summary.py /mnt/data/hugo_SBOM_syft.json --format tsv --out syft_schema.tsv

- Hmark/Hatbom wrapped SBOM (JSON output):
  python schema_summary.py /mnt/data/hugo_hmark_SBOM_hatbom.json --format json --out hmark_schema.json

Notes
-----
- This is a "schema summary from observed instances" (not an official CycloneDX schema validator).
- For very large SBOMs, JSON output is often easiest to post-process.
"""

import argparse
import json
from typing import Any, Dict, List, Set, Tuple


def type_name(x: Any) -> str:
    if x is None:
        return "null"
    if isinstance(x, bool):
        return "boolean"
    if isinstance(x, int) and not isinstance(x, bool):
        return "integer"
    if isinstance(x, float):
        return "number"
    if isinstance(x, str):
        return "string"
    if isinstance(x, dict):
        return "object"
    if isinstance(x, list):
        return "array"
    return type(x).__name__


class SchemaAgg:
    def __init__(self) -> None:
        self.types: Dict[str, Set[str]] = {}
        self.count: Dict[str, int] = {}
        self.samples: Dict[str, List[Any]] = {}

    def add(self, path: str, val: Any, sample_limit: int = 3) -> None:
        t = type_name(val)
        self.types.setdefault(path, set()).add(t)
        self.count[path] = self.count.get(path, 0) + 1

        # 샘플은 primitive만 조금 모아두기(너무 커지는 것 방지)
        if t in {"string", "integer", "number", "boolean", "null"}:
            s = self.samples.setdefault(path, [])
            if len(s) < sample_limit:
                s.append(val)


def walk_schema(obj: Any, agg: SchemaAgg, path: str = "") -> None:
    """
    Traverse JSON and aggregate normalized schema paths:
      - dict key: path.key
      - list: path[]  (index 제거)
    For leaves, record the leaf path with primitive type.
    For empty containers, record container path type as array/object too.
    """
    if isinstance(obj, dict):
        # 컨테이너 자체 타입도 기록(선택적으로 유용)
        if path != "":
            agg.add(path, obj)
        if not obj:
            return
        for k, v in obj.items():
            new_path = f"{path}.{k}" if path else str(k)
            walk_schema(v, agg, new_path)
        return

    if isinstance(obj, list):
        arr_path = f"{path}[]" if path else "[]"
        agg.add(arr_path, obj)  # array 타입 기록
        if not obj:
            return
        for v in obj:
            walk_schema(v, agg, arr_path)
        return

    # primitive leaf
    leaf_path = path if path else "$"
    agg.add(leaf_path, obj)


def render_markdown(agg: SchemaAgg, show_samples: bool = True) -> str:
    rows = []
    for p in sorted(agg.types.keys()):
        types = ", ".join(sorted(agg.types[p]))
        cnt = agg.count.get(p, 0)
        if show_samples:
            smp = agg.samples.get(p, [])
            smp_str = json.dumps(smp, ensure_ascii=False)
            rows.append((p, types, str(cnt), smp_str))
        else:
            rows.append((p, types, str(cnt)))

    if show_samples:
        header = ["Path", "Types", "Count", "Samples(primitive)"]
    else:
        header = ["Path", "Types", "Count"]

    md = []
    md.append("| " + " | ".join(header) + " |")
    md.append("|" + "|".join(["---"] * len(header)) + "|")
    for r in rows:
        md.append("| " + " | ".join(r) + " |")
    return "\n".join(md)


def render_tsv(agg: SchemaAgg, show_samples: bool = True) -> str:
    lines = []
    for p in sorted(agg.types.keys()):
        types = ",".join(sorted(agg.types[p]))
        cnt = agg.count.get(p, 0)
        if show_samples:
            smp = agg.samples.get(p, [])
            smp_str = json.dumps(smp, ensure_ascii=False)
            lines.append(f"{p}\t{types}\t{cnt}\t{smp_str}")
        else:
            lines.append(f"{p}\t{types}\t{cnt}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Schema summary for a JSON file (array indices collapsed to []).")
    ap.add_argument("json_file", help="Path to SBOM JSON")
    ap.add_argument("--out", default="", help="Output file path (omit to print)")
    ap.add_argument("--format", choices=["md", "tsv", "json"], default="md", help="Output format")
    ap.add_argument("--no-samples", action="store_true", help="Do not print primitive samples")
    args = ap.parse_args()

    with open(args.json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    agg = SchemaAgg()
    walk_schema(data, agg)

    show_samples = not args.no_samples

    if args.format == "md":
        content = render_markdown(agg, show_samples=show_samples) + "\n"
    elif args.format == "tsv":
        content = render_tsv(agg, show_samples=show_samples) + "\n"
    else:  # json
        # JSON 출력은 path별 타입/카운트/샘플 구조로 제공
        obj = {}
        for p in sorted(agg.types.keys()):
            obj[p] = {
                "types": sorted(agg.types[p]),
                "count": agg.count.get(p, 0),
            }
            if show_samples:
                obj[p]["samples"] = agg.samples.get(p, [])
        content = json.dumps(obj, ensure_ascii=False, indent=2) + "\n"

    if args.out:
        with open(args.out, "w", encoding="utf-8") as wf:
            wf.write(content)
    else:
        print(content, end="")


if __name__ == "__main__":
    main()
