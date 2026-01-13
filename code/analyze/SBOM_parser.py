#!/usr/bin/env python3
"""
Strict CISA SBOM Minimum Elements (11) checker for CycloneDX JSON SBOMs.

Output format:
- Metadata 5 fields: O / X
- Component 6 fields: coverage (%) over components[]

STRICT RULES (more strict than the previous script)
Metadata (O/X):
1) SBOM Author:
   - metadata.authors[] exists AND at least one author.name is non-empty AND not placeholder (e.g., "unknown").
2) Tool Name:
   - metadata.tools.components[] exists AND at least one tool has BOTH name and version (non-placeholder).
3) Timestamp:
   - metadata.timestamp parses as ISO-8601 AND includes timezone ("Z" or ±HH:MM).
4) Generation Context:
   - metadata.lifecycles[].phase exists AND phase is one of {"pre-build","build","post-build"}.
5) Dependency Relationship:
   - dependencies[] exists AND at least one edge (ref -> dependsOn[]) is non-empty
     AND both endpoints exist in known bom-ref set (components[]."bom-ref" plus metadata.component."bom-ref" if present).

Component coverages (% over components[]):
A) Producer %:
   - component.supplier.name OR component.manufacturer.name OR component.publisher exists (author/authors NOT counted).
B) Name %:
   - component.name exists AND not path-like (doesn't start with "/" or "./" or drive path like "C:\").
C) Version %:
   - component.version exists AND not placeholder/templated/UNKNOWN AND not "0.0.0*" pseudo-placeholder.
D) Identifiers %:
   - STRICT identifiers only:
     - purl with explicit version (contains "@") AND not pkg:generic/*
     - OR CPE v2.3-like string "cpe:2.3:*"
     - OR swid.tagId present
     - OR externalReferences has at least one http(s) URL
   - bom-ref is NOT counted as an identifier.
E) Hash %:
   - component.hashes contains at least one strong hash with valid length:
     SHA-256(64 hex), SHA-384(96 hex), SHA-512(128 hex)
     (MD5/SHA-1 are not counted).
F) License %:
   - component.licenses contains SPDX-like id OR a non-placeholder expression.
   - "UNKNOWN"/"NOASSERTION" etc. are not counted.

Usage:
  python cisa11_cdx_check_strict.py sbom1.json sbom2.json sbom3.json sbom4.json
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Set

# -----------------------------
# Strict patterns & constants
# -----------------------------

PLACEHOLDER_STR_RE = re.compile(r"^\s*$|^(unknown|n/a|na|null|none|noassertion)$", re.IGNORECASE)
TEMPLATED_VERSION_RE = re.compile(r"^@.+@$")                 # e.g., @spring-framework.version@
PSEUDO_PLACEHOLDER_VERSION_RE = re.compile(r"^0\.0\.0([\-+].*)?$")  # treat 0.0.0 / 0.0.0-xxx as placeholder

# Timestamp must include timezone
TZ_IN_TIMESTAMP_RE = re.compile(r"(Z|[+\-]\d{2}:\d{2})$")

# Strong hash algorithms allowed
ALLOWED_HASH_ALGS = {
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Accept only these lifecycle phases for strict "Generation Context"
ALLOWED_LIFECYCLE_PHASES = {"pre-build", "build", "post-build"}

# CPE v2.3 prefix check (strict-ish)
CPE23_RE = re.compile(r"^cpe:2\.3:[aho\*]:", re.IGNORECASE)

# purl strict: must have @version and not pkg:generic
PURL_STRICT_RE = re.compile(r"^pkg:(?!generic/).+@.+", re.IGNORECASE)

# path-like names we consider invalid in strict mode
PATHLIKE_NAME_RE = re.compile(r"^(\/|\.\/|[A-Za-z]:\\)")

# SPDX-ish ID pattern (not a full SPDX list validation, but strict enough)
SPDX_ID_RE = re.compile(r"^[A-Za-z0-9\.\-+]+$")


# -----------------------------
# Helpers
# -----------------------------

def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def unwrap_cyclonedx_root(doc: Dict[str, Any]) -> Dict[str, Any]:
    # Hatbom-like wrapper: {"sbom": {...}}
    if isinstance(doc, dict) and "sbom" in doc and isinstance(doc["sbom"], dict):
        inner = doc["sbom"]
        if inner.get("bomFormat") == "CycloneDX" or "components" in inner or "metadata" in inner:
            return inner
    return doc

def get_components(bom: Dict[str, Any]) -> List[Dict[str, Any]]:
    comps = bom.get("components", [])
    return comps if isinstance(comps, list) else []

def nonempty_str(x: Any) -> bool:
    return isinstance(x, str) and x.strip() != ""

def is_placeholder_str(x: Any) -> bool:
    return not nonempty_str(x) or bool(PLACEHOLDER_STR_RE.match(x.strip()))

def parse_iso8601_with_tz(ts: Any) -> bool:
    if not isinstance(ts, str) or is_placeholder_str(ts):
        return False
    if not TZ_IN_TIMESTAMP_RE.search(ts.strip()):
        return False
    try:
        t = ts.replace("Z", "+00:00")
        datetime.fromisoformat(t)
        return True
    except Exception:
        return False

def coverage(components: List[Dict[str, Any]], predicate) -> float:
    total = len(components)
    if total == 0:
        return 0.0
    ok = sum(1 for c in components if predicate(c))
    return round(ok * 100.0 / total, 1)

def known_bom_refs(bom: Dict[str, Any], components: List[Dict[str, Any]]) -> Set[str]:
    refs: Set[str] = set()
    for c in components:
        br = c.get("bom-ref")
        if nonempty_str(br):
            refs.add(br.strip())
    meta = bom.get("metadata")
    if isinstance(meta, dict):
        mc = meta.get("component")
        if isinstance(mc, dict) and nonempty_str(mc.get("bom-ref")):
            refs.add(mc["bom-ref"].strip())
    return refs


# -----------------------------
# Strict metadata (O/X)
# -----------------------------

def meta_sbom_author_strict(bom: Dict[str, Any]) -> bool:
    meta = bom.get("metadata")
    if not isinstance(meta, dict):
        return False
    authors = meta.get("authors")
    if not isinstance(authors, list) or len(authors) == 0:
        return False
    for a in authors:
        if isinstance(a, dict):
            name = a.get("name")
            if nonempty_str(name) and not is_placeholder_str(name):
                return True
    return False

def meta_tool_name_strict(bom: Dict[str, Any]) -> bool:
    meta = bom.get("metadata")
    if not isinstance(meta, dict):
        return False
    tools = meta.get("tools")
    if not isinstance(tools, dict):
        return False
    comps = tools.get("components")
    if not isinstance(comps, list) or len(comps) == 0:
        return False
    for t in comps:
        if not isinstance(t, dict):
            continue
        name = t.get("name")
        ver = t.get("version")
        if nonempty_str(name) and not is_placeholder_str(name) and nonempty_str(ver) and not is_placeholder_str(ver):
            return True
    return False

def meta_timestamp_strict(bom: Dict[str, Any]) -> bool:
    meta = bom.get("metadata")
    if not isinstance(meta, dict):
        return False
    return parse_iso8601_with_tz(meta.get("timestamp"))

def meta_generation_context_strict(bom: Dict[str, Any]) -> bool:
    meta = bom.get("metadata")
    if not isinstance(meta, dict):
        return False
    lifecycles = meta.get("lifecycles")
    if not isinstance(lifecycles, list) or len(lifecycles) == 0:
        return False
    for lc in lifecycles:
        if isinstance(lc, dict) and nonempty_str(lc.get("phase")):
            phase = lc["phase"].strip()
            if phase in ALLOWED_LIFECYCLE_PHASES:
                return True
    return False

def meta_dependency_relationship_strict(bom: Dict[str, Any], refset: Set[str]) -> bool:
    deps = bom.get("dependencies")
    if not isinstance(deps, list) or len(deps) == 0:
        return False
    # Need at least one valid edge: ref -> dependsOn (non-empty), both endpoints known
    for d in deps:
        if not isinstance(d, dict):
            continue
        ref = d.get("ref")
        depends_on = d.get("dependsOn")
        if not nonempty_str(ref) or ref.strip() not in refset:
            continue
        if not isinstance(depends_on, list) or len(depends_on) == 0:
            continue
        # At least one dependsOn target must be known
        for t in depends_on:
            if nonempty_str(t) and t.strip() in refset:
                return True
    return False


# -----------------------------
# Strict component coverages (%)
# -----------------------------

def comp_producer_strict(c: Dict[str, Any]) -> bool:
    # Strict: only supplier/manufacturer/publisher count. (Not author/authors.)
    supplier = c.get("supplier")
    if isinstance(supplier, dict) and nonempty_str(supplier.get("name")) and not is_placeholder_str(supplier.get("name")):
        return True
    manufacturer = c.get("manufacturer")
    if isinstance(manufacturer, dict) and nonempty_str(manufacturer.get("name")) and not is_placeholder_str(manufacturer.get("name")):
        return True
    pub = c.get("publisher")
    if nonempty_str(pub) and not is_placeholder_str(pub):
        return True
    return False

def comp_name_strict(c: Dict[str, Any]) -> bool:
    name = c.get("name")
    if not nonempty_str(name) or is_placeholder_str(name):
        return False
    if PATHLIKE_NAME_RE.match(name.strip()):
        return False
    return True

def comp_version_strict(c: Dict[str, Any]) -> bool:
    v = c.get("version")
    if not isinstance(v, str):
        return False
    vs = v.strip()
    if is_placeholder_str(vs):
        return False
    if TEMPLATED_VERSION_RE.match(vs):
        return False
    if vs.upper() == "UNKNOWN":
        return False
    if PSEUDO_PLACEHOLDER_VERSION_RE.match(vs):
        return False
    return True

def comp_identifiers_strict(c: Dict[str, Any]) -> bool:
    purl = c.get("purl")
    if isinstance(purl, str) and PURL_STRICT_RE.match(purl.strip()):
        return True

    cpe = c.get("cpe")
    if isinstance(cpe, str) and CPE23_RE.match(cpe.strip()):
        return True

    swid = c.get("swid")
    if isinstance(swid, dict) and nonempty_str(swid.get("tagId")) and not is_placeholder_str(swid.get("tagId")):
        return True

    ext = c.get("externalReferences")
    if isinstance(ext, list):
        for e in ext:
            if isinstance(e, dict):
                url = e.get("url")
                if isinstance(url, str) and url.strip().lower().startswith(("http://", "https://")):
                    return True

    return False

def comp_hash_strict(c: Dict[str, Any]) -> bool:
    hashes = c.get("hashes")
    if not isinstance(hashes, list) or len(hashes) == 0:
        return False
    for h in hashes:
        if not isinstance(h, dict):
            continue
        alg = h.get("alg")
        content = h.get("content")
        if not (isinstance(alg, str) and isinstance(content, str)):
            continue
        algs = alg.strip().upper()
        # Normalize some common variations
        norm = algs.replace("SHA256", "SHA-256").replace("SHA384", "SHA-384").replace("SHA512", "SHA-512")
        if norm not in ALLOWED_HASH_ALGS:
            continue
        hexs = content.strip()
        if not HEX_RE.match(hexs):
            continue
        if len(hexs) != ALLOWED_HASH_ALGS[norm]:
            continue
        return True
    return False

def comp_license_strict(c: Dict[str, Any]) -> bool:
    licenses = c.get("licenses")
    if not isinstance(licenses, list) or len(licenses) == 0:
        return False
    for item in licenses:
        if not isinstance(item, dict):
            continue

        expr = item.get("expression")
        if isinstance(expr, str):
            ex = expr.strip()
            if nonempty_str(ex) and not is_placeholder_str(ex) and ex.upper() != "NOASSERTION":
                return True

        lic = item.get("license")
        if isinstance(lic, dict):
            lid = lic.get("id")
            if isinstance(lid, str):
                s = lid.strip()
                if nonempty_str(s) and not is_placeholder_str(s) and s.upper() != "NOASSERTION" and SPDX_ID_RE.match(s):
                    return True
            # In strict mode, name alone is weak; still accept if it's not placeholder and looks SPDX-ish
            lname = lic.get("name")
            if isinstance(lname, str):
                s = lname.strip()
                if nonempty_str(s) and not is_placeholder_str(s) and s.upper() != "NOASSERTION":
                    return True

    return False


# -----------------------------
# Evaluation + printing
# -----------------------------

def evaluate_bom_strict(path: str) -> Dict[str, Any]:
    doc = load_json(path)
    bom = unwrap_cyclonedx_root(doc)
    comps = get_components(bom)
    refset = known_bom_refs(bom, comps)

    return {
        "file": os.path.basename(path),
        "Component Count": len(comps),

        # Metadata 5 (O/X)
        "SBOM Author": "O" if meta_sbom_author_strict(bom) else "X",
        "Tool Name": "O" if meta_tool_name_strict(bom) else "X",
        "Timestamp": "O" if meta_timestamp_strict(bom) else "X",
        "Generation Context": "O" if meta_generation_context_strict(bom) else "X",
        "Dependency Relationship": "O" if meta_dependency_relationship_strict(bom, refset) else "X",

        # Component 6 (%)
        "Producer %": coverage(comps, comp_producer_strict),
        "Name %": coverage(comps, comp_name_strict),
        "Version %": coverage(comps, comp_version_strict),
        "Identifiers %": coverage(comps, comp_identifiers_strict),
        "Hash %": coverage(comps, comp_hash_strict),
        "License %": coverage(comps, comp_license_strict),
    }

def print_markdown_table(rows: List[Dict[str, Any]]) -> None:
    cols = [
        "SBOM Author", "Tool Name", "Timestamp", "Generation Context", "Dependency Relationship",
        "Producer %", "Name %", "Version %", "Identifiers %", "Hash %", "License %"
    ]
    print("| " + " | ".join(cols) + " |")
    print("|" + "|".join(["---"] * len(cols)) + "|")
    for r in rows:
        out = []
        for c in cols:
            v = r[c]
            if isinstance(v, float):
                out.append(f"{v:.1f}")
            else:
                out.append(str(v))
        print("| " + " | ".join(out) + " |")

def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("Usage: python cisa11_cdx_check_strict.py <sbom1.json> [sbom2.json ...]")
        return 2

    rows = [evaluate_bom_strict(p) for p in argv[1:]]

    # Print component counts to stderr so the markdown table stays clean
    for r in rows:
        sys.stderr.write(f"- {r['file']}: components={r['Component Count']}\n")

    print_markdown_table(rows)
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))