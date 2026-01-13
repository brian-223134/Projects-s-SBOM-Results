#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CISA SBOM Minimum Elements (11 fields) coverage parser for CycloneDX JSON.

- Accepts 1..N SBOM JSON files
- Component count denominator:
  - Normal CycloneDX: $.components.length
  - Wrapped (Hatbom/Hmark): $.sbom.components.length
  - Excludes: metadata.component
  - dependencies[] is NOT part of component denominator

Outputs:
1) Coverage table (O/X + %)
2) Evidence per file (why O/X, and numerator/denominator for %)

Usage:
  python sbom_cisa_min_elements.py <sbom1.json> [<sbom2.json> ...]
Optional:
  --labels <label1> [<label2> ...]   (if fewer than files, rest auto-filled)
  --no-evidence
"""

import argparse
import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

_PLACEHOLDER_VERSION = {"unknown", "n/a", "na", "null", "none"}

def _nonempty_str(x: Any) -> bool:
    return isinstance(x, str) and x.strip() != ""

def _iso8601_parseable(ts: Any) -> bool:
    if not _nonempty_str(ts):
        return False
    s = ts.strip()
    s2 = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        _dt.datetime.fromisoformat(s2)
        return True
    except Exception:
        pat = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
        return re.match(pat, s) is not None

def _is_wrapped(doc: Dict[str, Any]) -> bool:
    return isinstance(doc, dict) and isinstance(doc.get("sbom"), dict)

def _root(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc["sbom"] if _is_wrapped(doc) else doc

def _metadata(doc: Dict[str, Any]) -> Dict[str, Any]:
    md = _root(doc).get("metadata")
    return md if isinstance(md, dict) else {}

def _components(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    comps = _root(doc).get("components", [])
    if not isinstance(comps, list):
        return []
    return [c for c in comps if isinstance(c, dict)]

# 1) SBOM Author (O/X): metadata.authors[].name
def check_sbom_author(doc: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    md = _metadata(doc)
    authors = md.get("authors")
    names: List[str] = []
    if isinstance(authors, list):
        for a in authors:
            if isinstance(a, dict) and _nonempty_str(a.get("name")):
                names.append(a["name"].strip())
    ok = len(names) > 0
    return ok, {
        "jsonpath": "$.metadata.authors[].name" if not _is_wrapped(doc) else "$.sbom.metadata.authors[].name",
        "found_names": names,
    }

# 9) Tool Name (O/X): metadata.tools.components[].name (+ fallback)
def _extract_tool_names(doc: Dict[str, Any]) -> List[str]:
    md = _metadata(doc)
    tools = md.get("tools")
    names: List[str] = []

    # Standard: tools: { components: [ {name:...}, ... ] }
    if isinstance(tools, dict):
        comps = tools.get("components")
        if isinstance(comps, list):
            for c in comps:
                if isinstance(c, dict) and _nonempty_str(c.get("name")):
                    names.append(c["name"].strip())

    # Non-standard: tools: [ {name:...}, ... ]
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict) and _nonempty_str(t.get("name")):
                names.append(t["name"].strip())
            elif isinstance(t, str) and t.strip():
                names.append(t.strip())

    # Optional fallback: annotations.annotator.component.name
    ann = _root(doc).get("annotations")
    if isinstance(ann, list):
        for a in ann:
            if not isinstance(a, dict):
                continue
            annotator = a.get("annotator")
            if not isinstance(annotator, dict):
                continue
            comp = annotator.get("component")
            if isinstance(comp, dict) and _nonempty_str(comp.get("name")):
                names.append(comp["name"].strip())

    # de-dup preserve order
    seen = set()
    uniq: List[str] = []
    for n in names:
        if n not in seen:
            uniq.append(n)
            seen.add(n)
    return uniq

def check_tool_name(doc: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    names = _extract_tool_names(doc)
    ok = len(names) > 0
    return ok, {
        "primary_jsonpath": "$.metadata.tools.components[].name" if not _is_wrapped(doc) else "$.sbom.metadata.tools.components[].name",
        "fallback_jsonpath": "$.annotations[].annotator.component.name" if not _is_wrapped(doc) else "$.sbom.annotations[].annotator.component.name",
        "found_names": names,
    }

# 10) Timestamp (O/X): metadata.timestamp ISO8601
def check_timestamp(doc: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    md = _metadata(doc)
    ts = md.get("timestamp")
    ok = _iso8601_parseable(ts)
    return ok, {
        "jsonpath": "$.metadata.timestamp" if not _is_wrapped(doc) else "$.sbom.metadata.timestamp",
        "value": ts,
        "iso8601_ok": ok,
    }

# 11) Generation Context (O/X): metadata.lifecycles[].phase
def check_generation_context(doc: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    md = _metadata(doc)
    lifecycles = md.get("lifecycles")
    phases: List[str] = []
    if isinstance(lifecycles, list):
        for l in lifecycles:
            if isinstance(l, dict) and _nonempty_str(l.get("phase")):
                phases.append(l["phase"].strip())
    ok = len(phases) > 0
    return ok, {
        "jsonpath": "$.metadata.lifecycles[].phase" if not _is_wrapped(doc) else "$.sbom.metadata.lifecycles[].phase",
        "found_phases": phases,
    }

# 8) Dependency Relationship (O/X): dependencies[] + ref/dependsOn edge exists
def check_dependency_relationship(doc: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    deps = _root(doc).get("dependencies")
    if not isinstance(deps, list) or len(deps) == 0:
        return False, {
            "jsonpath": "$.dependencies[]" if not _is_wrapped(doc) else "$.sbom.dependencies[]",
            "reason": "dependencies[] missing or empty",
            "edges_found": 0,
        }

    edges = 0
    for d in deps:
        if not isinstance(d, dict):
            continue
        ref = d.get("ref")
        depends_on = d.get("dependsOn")
        if _nonempty_str(ref) and isinstance(depends_on, list):
            edges += sum(1 for x in depends_on if _nonempty_str(x))

    ok = edges > 0
    return ok, {
        "jsonpath": "$.dependencies[]" if not _is_wrapped(doc) else "$.sbom.dependencies[]",
        "edges_found": edges,
        "ok_rule": "exists at least one non-empty (ref -> dependsOn) edge",
    }

# Component-level checks (%)
def comp_has_producer(c: Dict[str, Any]) -> bool:
    man = c.get("manufacturer")
    sup = c.get("supplier")
    pub = c.get("publisher")
    if isinstance(man, dict) and _nonempty_str(man.get("name")):
        return True
    if isinstance(sup, dict) and _nonempty_str(sup.get("name")):
        return True
    if _nonempty_str(pub):
        return True
    
    # 2) Extended 후보: component authors/author
    # - authors: [{name: "..."}]
    authors = c.get("authors")
    if isinstance(authors, list):
        for a in authors:
            if isinstance(a, dict) and _nonempty_str(a.get("name")):
                return True

    # - author: "..." (CycloneDX에서 단일 author 문자열로 나오는 경우도 있음)
    
    if _nonempty_str(c.get("author")):
        return True
    return False

def comp_has_name(c: Dict[str, Any]) -> bool:
    return _nonempty_str(c.get("name"))

def comp_has_version(c: Dict[str, Any]) -> bool:
    v = c.get("version")
    if v is None:
        return False
    if isinstance(v, str):
        vv = v.strip()
        if vv == "":
            return False
        if vv.lower() in _PLACEHOLDER_VERSION:
            return False
        return True
    return True

def comp_has_identifiers(c: Dict[str, Any]) -> bool:
    if _nonempty_str(c.get("purl")):
        return True
    if _nonempty_str(c.get("cpe")):
        return True

    swid = c.get("swid")
    if isinstance(swid, dict):
        for k in ("tagId", "name", "version", "text"):
            if _nonempty_str(swid.get(k)):
                return True

    ext = c.get("externalReferences")
    if isinstance(ext, list) and len(ext) > 0:
        return True

    bref = c.get("bom-ref")
    if _nonempty_str(bref) and re.match(r"^(pkg:|urn:)", bref.strip()):
        return True

    return False

def comp_has_hash(c: Dict[str, Any]) -> bool:
    hashes = c.get("hashes")
    if not isinstance(hashes, list):
        return False
    for h in hashes:
        if isinstance(h, dict) and _nonempty_str(h.get("alg")) and _nonempty_str(h.get("content")):
            return True
    return False

def comp_has_license(c: Dict[str, Any]) -> bool:
    licenses = c.get("licenses")
    if not isinstance(licenses, list) or len(licenses) == 0:
        return False
    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        if _nonempty_str(entry.get("expression")):
            return True
        lic = entry.get("license")
        if isinstance(lic, dict) and (_nonempty_str(lic.get("id")) or _nonempty_str(lic.get("name"))):
            return True
    return False

def _pct(numer: int, denom: int) -> float:
    return 0.0 if denom <= 0 else (numer / denom) * 100.0

def analyze(doc: Dict[str, Any]) -> Dict[str, Any]:
    comps = _components(doc)
    denom = len(comps)

    sbom_author_ok, sbom_author_evi = check_sbom_author(doc)
    tool_ok, tool_evi = check_tool_name(doc)
    ts_ok, ts_evi = check_timestamp(doc)
    gen_ok, gen_evi = check_generation_context(doc)
    dep_ok, dep_evi = check_dependency_relationship(doc)

    producer_n = sum(1 for c in comps if comp_has_producer(c))
    name_n = sum(1 for c in comps if comp_has_name(c))
    version_n = sum(1 for c in comps if comp_has_version(c))
    id_n = sum(1 for c in comps if comp_has_identifiers(c))
    hash_n = sum(1 for c in comps if comp_has_hash(c))
    lic_n = sum(1 for c in comps if comp_has_license(c))

    return {
        "wrapped": _is_wrapped(doc),
        "denom": denom,
        "sbom_author": {"ok": sbom_author_ok, "evidence": sbom_author_evi},
        "tool_name": {"ok": tool_ok, "evidence": tool_evi},
        "timestamp": {"ok": ts_ok, "evidence": ts_evi},
        "generation_context": {"ok": gen_ok, "evidence": gen_evi},
        "dependency_relationship": {"ok": dep_ok, "evidence": dep_evi},
        "producer": {"numer": producer_n, "pct": _pct(producer_n, denom)},
        "name": {"numer": name_n, "pct": _pct(name_n, denom)},
        "version": {"numer": version_n, "pct": _pct(version_n, denom)},
        "identifiers": {"numer": id_n, "pct": _pct(id_n, denom)},
        "hash": {"numer": hash_n, "pct": _pct(hash_n, denom)},
        "license": {"numer": lic_n, "pct": _pct(lic_n, denom)},
    }

def fmt_ox(ok: bool) -> str:
    return "O" if ok else "X"

def fmt_pct(x: float) -> str:
    return f"{x:.1f}"

def print_table(rows: List[Tuple[str, Dict[str, Any]]]) -> None:
    header = [
        "SBOM Author", "Tool Name", "Timestamp", "Generation Context", "Dependency Relationship",
        "Producer %", "Name %", "Version %", "Identifiers %", "Hash %", "License %"
    ]
    print("| " + " | ".join(header) + " |")
    print("|" + "|".join(["---"] * len(header)) + "|")

    for label, r in rows:
        line = [
            fmt_ox(r["sbom_author"]["ok"]),
            fmt_ox(r["tool_name"]["ok"]),
            fmt_ox(r["timestamp"]["ok"]),
            fmt_ox(r["generation_context"]["ok"]),
            fmt_ox(r["dependency_relationship"]["ok"]),
            fmt_pct(r["producer"]["pct"]),
            fmt_pct(r["name"]["pct"]),
            fmt_pct(r["version"]["pct"]),
            fmt_pct(r["identifiers"]["pct"]),
            fmt_pct(r["hash"]["pct"]),
            fmt_pct(r["license"]["pct"]),
        ]
        print(f"| {label} | " + " | ".join(line) + " |")

def _comp_hint(c: Dict[str, Any]) -> str:
    for k in ("bom-ref", "purl", "name"):
        v = c.get(k)
        if _nonempty_str(v):
            return v.strip()
    return "<unknown>"

def print_evidence(label: str, r: Dict[str, Any], doc: Dict[str, Any]) -> None:
    denom = r["denom"]
    wrapper = "wrapped($.sbom.*)" if r["wrapped"] else "normal($.*)"
    print(f"\n## {label}")
    print(f"- Format: {wrapper}")
    print(f"- Component count (denominator): {denom}")

    a = r["sbom_author"]["evidence"]
    t = r["tool_name"]["evidence"]
    ts = r["timestamp"]["evidence"]
    gc = r["generation_context"]["evidence"]
    dep = r["dependency_relationship"]["evidence"]

    print("\n### SBOM-level (O/X) evidence")
    print(f"- SBOM Author: {fmt_ox(r['sbom_author']['ok'])}  (path: {a.get('jsonpath')}, found: {a.get('found_names')})")
    print(f"- Tool Name: {fmt_ox(r['tool_name']['ok'])}  (primary: {t.get('primary_jsonpath')}, fallback: {t.get('fallback_jsonpath')}, found: {t.get('found_names')})")
    print(f"- Timestamp: {fmt_ox(r['timestamp']['ok'])}  (path: {ts.get('jsonpath')}, value: {ts.get('value')}, iso8601_ok={ts.get('iso8601_ok')})")
    print(f"- Generation Context: {fmt_ox(r['generation_context']['ok'])}  (path: {gc.get('jsonpath')}, found phases: {gc.get('found_phases')})")
    print(f"- Dependency Relationship: {fmt_ox(r['dependency_relationship']['ok'])}  (path: {dep.get('jsonpath')}, edges_found={dep.get('edges_found')})")

    print("\n### Component-level (%) evidence")
    print(f"- Producer: {r['producer']['numer']}/{denom} = {fmt_pct(r['producer']['pct'])}%  (manufacturer.name / supplier.name / publisher)")
    print(f"- Name: {r['name']['numer']}/{denom} = {fmt_pct(r['name']['pct'])}%  (components[].name)")
    print(f"- Version: {r['version']['numer']}/{denom} = {fmt_pct(r['version']['pct'])}%  (components[].version, excluding placeholders)")
    print(f"- Identifiers: {r['identifiers']['numer']}/{denom} = {fmt_pct(r['identifiers']['pct'])}%  (purl/cpe/swid/externalReferences/bom-ref(pkg|urn))")
    print(f"- Hash: {r['hash']['numer']}/{denom} = {fmt_pct(r['hash']['pct'])}%  (hashes[].alg + hashes[].content)")
    print(f"- License: {r['license']['numer']}/{denom} = {fmt_pct(r['license']['pct'])}%  (licenses[].license.id|name or licenses[].expression)")

    comps = _components(doc)

    def show_missing(title: str, predicate):
        missing = [c for c in comps if not predicate(c)]
        if len(missing) == 0:
            return
        if len(missing) == denom:
            print(f"  - Missing {title}: ALL components")
            return
        sample = [_comp_hint(c) for c in missing[:5]]
        print(f"  - Missing {title}: {len(missing)} comps (sample up to 5): {sample}")

    print("\n### Missing samples (only when not 100%)")
    show_missing("Producer", comp_has_producer)
    show_missing("Version", comp_has_version)
    show_missing("Identifiers", comp_has_identifiers)
    show_missing("Hash", comp_has_hash)
    show_missing("License", comp_has_license)

def load_json(path: str) -> Dict[str, Any]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def build_labels(paths: List[str], user_labels: List[str]) -> List[str]:
    auto = [Path(p).name for p in paths]
    if not user_labels:
        return auto
    # if labels fewer than files, fill the rest automatically
    out = []
    for i, p in enumerate(paths):
        if i < len(user_labels) and user_labels[i].strip():
            out.append(user_labels[i].strip())
        else:
            out.append(auto[i])
    return out

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("sboms", nargs="+", help="One or more CycloneDX SBOM JSON files")
    ap.add_argument("--labels", nargs="*", default=[], help="Optional labels (can be fewer than files)")
    ap.add_argument("--no-evidence", action="store_true", help="Print only the table")
    args = ap.parse_args()

    paths = args.sboms
    labels = build_labels(paths, args.labels)

    docs = [load_json(p) for p in paths]
    analyses = [analyze(d) for d in docs]
    rows = list(zip(labels, analyses))

    # Table with label column
    # (prepend label column in header for readability)
    header = [
        "File/Label", "SBOM Author", "Tool Name", "Timestamp", "Generation Context", "Dependency Relationship",
        "Producer %", "Name %", "Version %", "Identifiers %", "Hash %", "License %"
    ]
    print("| " + " | ".join(header) + " |")
    print("|" + "|".join(["---"] * len(header)) + "|")
    for label, r in rows:
        line = [
            label,
            fmt_ox(r["sbom_author"]["ok"]),
            fmt_ox(r["tool_name"]["ok"]),
            fmt_ox(r["timestamp"]["ok"]),
            fmt_ox(r["generation_context"]["ok"]),
            fmt_ox(r["dependency_relationship"]["ok"]),
            fmt_pct(r["producer"]["pct"]),
            fmt_pct(r["name"]["pct"]),
            fmt_pct(r["version"]["pct"]),
            fmt_pct(r["identifiers"]["pct"]),
            fmt_pct(r["hash"]["pct"]),
            fmt_pct(r["license"]["pct"]),
        ]
        print("| " + " | ".join(line) + " |")

    if not args.no_evidence:
        for label, r, doc in zip(labels, analyses, docs):
            print_evidence(label, r, doc)

if __name__ == "__main__":
    main()