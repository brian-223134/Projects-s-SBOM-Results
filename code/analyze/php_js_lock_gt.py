#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP/JS lockfile ground-truth extractor.

Scans a project tree and extracts a resolved dependency ground-truth (GT) set from:
- Composer: composer.lock (+ composer.json to mark direct deps)
- npm: package-lock.json (lockfileVersion 2/3; best support for v3 used by coolify)

This GT is intended to validate SBOM outputs (CycloneDX JSON) produced by tools
like syft/trivy/cdxgen.

Usage (coolify example):
  python code/analyze/php_js_lock_gt.py \
    --root languages/php/project/coolify \
    --out-dir code/analyze/out/php-js-gt-coolify

Outputs:
- php_js_lock_gt.json
- composer_deps.csv
- npm_deps.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote


@dataclass(frozen=True)
class Dep:
    ecosystem: str  # "composer" | "npm"
    name: str
    version: str
    direct: bool
    dev: bool
    manifest: str

    def to_purl(self) -> str:
        if self.ecosystem == "composer":
            # name is already "vendor/package"
            return f"pkg:composer/{self.name}@{self.version}"
        if self.ecosystem == "npm":
            # Encode @scope as %40 per purl conventions and common SBOM output.
            # Keep '/' unescaped so scoped packages remain readable.
            encoded = quote(self.name, safe="/@")
            encoded = encoded.replace("@", "%40")
            return f"pkg:npm/{encoded}@{self.version}"
        raise ValueError(f"Unsupported ecosystem: {self.ecosystem}")


def _load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _iter_manifest_files(root: Path) -> Iterable[Path]:
    wanted = {"composer.lock", "composer.json", "package-lock.json", "package.json"}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name in wanted:
            yield p


def _platform_composer_name(name: str) -> bool:
    # composer.json can include platform constraints like "php" or "ext-json".
    if name == "php":
        return True
    if name.startswith("ext-"):
        return True
    if name.startswith("lib-"):
        return True
    return False


def _read_composer_direct_sets(composer_json_path: Path) -> Tuple[Set[str], Set[str], str]:
    if not composer_json_path.exists():
        return set(), set(), ""
    doc = _load_json(composer_json_path)
    proj = str(doc.get("name") or "")

    require = doc.get("require") or {}
    require_dev = doc.get("require-dev") or {}

    direct = {k for k in require.keys() if isinstance(k, str) and not _platform_composer_name(k)}
    direct_dev = {k for k in require_dev.keys() if isinstance(k, str) and not _platform_composer_name(k)}
    return direct, direct_dev, proj


def extract_composer_lock(lock_path: Path) -> Tuple[List[Dep], Dict]:
    doc = _load_json(lock_path)

    base_dir = lock_path.parent
    composer_json_path = base_dir / "composer.json"
    direct, direct_dev, project_name = _read_composer_direct_sets(composer_json_path)

    out: List[Dep] = []

    def _consume(packages: Sequence[Dict], dev: bool) -> None:
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            if _platform_composer_name(name):
                continue

            is_direct = name in (direct_dev if dev else direct)
            out.append(
                Dep(
                    ecosystem="composer",
                    name=name,
                    version=version,
                    direct=is_direct,
                    dev=dev,
                    manifest=lock_path.as_posix(),
                )
            )

    _consume(doc.get("packages") or [], dev=False)
    _consume(doc.get("packages-dev") or [], dev=True)

    meta = {
        "type": "composer",
        "file": lock_path.as_posix(),
        "project_name": project_name,
        "content_hash": doc.get("content-hash"),
        "package_count": len(out),
    }
    return out, meta


def _npm_name_from_packages_key(key: str) -> Optional[str]:
    # keys look like:
    #   "" (root)
    #   "node_modules/axios"
    #   "node_modules/@xterm/xterm"
    #   "node_modules/a/node_modules/b"  (nested)
    if not isinstance(key, str) or not key:
        return None
    if "node_modules/" not in key:
        return None
    tail = key.split("node_modules/", 1)[1]
    # tail can still contain nested node_modules
    if "/node_modules/" in tail:
        tail = tail.rsplit("/node_modules/", 1)[1]
    return tail.strip() or None


def extract_package_lock(lock_path: Path) -> Tuple[List[Dep], Dict]:
    doc = _load_json(lock_path)

    lockfile_version = doc.get("lockfileVersion")
    packages = doc.get("packages")

    if not isinstance(packages, dict):
        raise ValueError(f"Unsupported package-lock format (missing 'packages'): {lock_path}")

    root_pkg = packages.get("") or {}
    direct_deps = set()
    direct_dev_deps = set()

    if isinstance(root_pkg, dict):
        deps = root_pkg.get("dependencies")
        dev_deps = root_pkg.get("devDependencies")
        if isinstance(deps, dict):
            direct_deps = {k for k in deps.keys() if isinstance(k, str)}
        if isinstance(dev_deps, dict):
            direct_dev_deps = {k for k in dev_deps.keys() if isinstance(k, str)}

    out: List[Dep] = []

    for k, v in packages.items():
        if k == "":
            continue
        if not isinstance(v, dict):
            continue

        name = _npm_name_from_packages_key(k)
        if not name:
            continue

        version = v.get("version")
        if not isinstance(version, str) or not version.strip():
            continue

        if v.get("link") is True:
            # local link/workspace
            continue

        is_dev = bool(v.get("dev"))
        is_direct = (name in direct_deps) or (name in direct_dev_deps)

        # If direct is only in devDependencies but not in dependencies, mark dev.
        if name in direct_dev_deps and name not in direct_deps:
            is_dev = True

        out.append(
            Dep(
                ecosystem="npm",
                name=name,
                version=version.strip(),
                direct=is_direct,
                dev=is_dev,
                manifest=lock_path.as_posix(),
            )
        )

    meta = {
        "type": "npm",
        "file": lock_path.as_posix(),
        "project_name": str(doc.get("name") or ""),
        "lockfile_version": lockfile_version,
        "package_count": len(out),
    }
    return out, meta


def _write_json(out_path: Path, payload: object) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Dep]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ecosystem", "name", "version", "direct", "dev", "purl", "manifest"])
        for d in sorted(rows, key=lambda x: (x.ecosystem, x.name, x.version, x.manifest)):
            w.writerow([d.ecosystem, d.name, d.version, "true" if d.direct else "false", "true" if d.dev else "false", d.to_purl(), d.manifest])


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract GT dependencies from composer.lock and package-lock.json")
    ap.add_argument("--root", type=Path, required=True, help="Project root to scan")
    ap.add_argument("--out-dir", type=Path, required=True, help="Output directory")
    ap.add_argument("--exclude-dev", action="store_true", help="Exclude dev dependencies")
    args = ap.parse_args()

    root: Path = args.root
    out_dir: Path = args.out_dir

    composer_locks = sorted(root.rglob("composer.lock"))
    package_locks = sorted(root.rglob("package-lock.json"))

    manifests_meta: List[Dict] = []
    deps: List[Dep] = []

    for p in composer_locks:
        d, meta = extract_composer_lock(p)
        manifests_meta.append(meta)
        deps.extend(d)

    for p in package_locks:
        d, meta = extract_package_lock(p)
        manifests_meta.append(meta)
        deps.extend(d)

    if args.exclude_dev:
        deps = [d for d in deps if not d.dev]

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": root.as_posix(),
        "manifests": manifests_meta,
        "dependencies": [
            {
                **asdict(d),
                "purl": d.to_purl(),
            }
            for d in deps
        ],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    _write_json(out_dir / "php_js_lock_gt.json", payload)

    composer_deps = [d for d in deps if d.ecosystem == "composer"]
    npm_deps = [d for d in deps if d.ecosystem == "npm"]

    _write_csv(out_dir / "composer_deps.csv", composer_deps)
    _write_csv(out_dir / "npm_deps.csv", npm_deps)

    print(f"Found composer.lock: {len(composer_locks)} | package-lock.json: {len(package_locks)}")
    print(f"GT deps: {len(deps)} (composer={len(composer_deps)}, npm={len(npm_deps)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
