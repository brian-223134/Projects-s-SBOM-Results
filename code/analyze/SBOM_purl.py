#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract component identifiers (purl preferred, else name) from CycloneDX JSON SBOM.

- Accepts 1..N SBOM JSON files
- Handles wrapped Hatbom/Hmark format where the document is under $.sbom
- Reads components from:
  - Normal CycloneDX: $.components[]
  - Wrapped: $.sbom.components[]

Usage:
  python SBOM_purl.py <sbom1.json> [<sbom2.json> ...]

Options:
  --unique        De-duplicate values per file (preserve first-seen order)
  --with-file     Prefix each line with "<filename>\t" for easy Excel import
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _nonempty_str(x: Any) -> bool:
    return isinstance(x, str) and x.strip() != ""


def _is_wrapped(doc: Dict[str, Any]) -> bool:
    return isinstance(doc, dict) and isinstance(doc.get("sbom"), dict)


def _root(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc["sbom"] if _is_wrapped(doc) else doc


def _components(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    comps = _root(doc).get("components", [])
    if not isinstance(comps, list):
        return []
    return [c for c in comps if isinstance(c, dict)]


def _extract_ids(doc: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for c in _components(doc):
        purl = c.get("purl")
        if _nonempty_str(purl):
            out.append(purl.strip())
            continue

        name = c.get("name")
        if _nonempty_str(name):
            out.append(name.strip())
            continue

    return out


def _dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for v in values:
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def load_json(path: str) -> Dict[str, Any]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract purl (else name) from CycloneDX SBOM components")
    ap.add_argument("sboms", nargs="+", help="One or more CycloneDX SBOM JSON files")
    ap.add_argument("--unique", action="store_true", help="De-duplicate extracted values per file")
    ap.add_argument("--with-file", action="store_true", help="Prefix each line with <filename>\\t")
    args = ap.parse_args()

    for sbom_path in args.sboms:
        doc = load_json(sbom_path)
        values = _extract_ids(doc)
        if args.unique:
            values = _dedupe_preserve_order(values)

        prefix = f"{Path(sbom_path).name}\t" if args.with_file else ""
        for v in values:
            print(prefix + v)


if __name__ == "__main__":
    main()
