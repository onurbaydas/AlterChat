#!/usr/bin/env python3
"""Fail if Tauri npm packages and Rust crates are on different major.minor.

`tauri build` refuses to bundle when e.g. tauri-plugin-opener 2.7 is paired
with @tauri-apps/plugin-opener 2.5. Running this in CI catches the mismatch on
the pull request instead of in the release job.

Usage: python scripts/check_tauri_versions.py [repo_root]
"""
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
lock = (root / "Cargo.lock").read_text(encoding="utf-8")
crates = dict(re.findall(r'name = "(tauri(?:-plugin-[a-z-]+)?)"\nversion = "([^"]+)"', lock))

npm_lock = json.loads((root / "alterchat-ui" / "package-lock.json").read_text(encoding="utf-8"))
packages = npm_lock.get("packages", {})


def npm_version(name: str):
    entry = packages.get(f"node_modules/{name}")
    return entry and entry.get("version")


def major_minor(v: str) -> str:
    return ".".join(v.split(".")[:2])


pairs = [("tauri", "@tauri-apps/api")]
for crate in crates:
    if crate.startswith("tauri-plugin-"):
        pairs.append((crate, "@tauri-apps/plugin-" + crate[len("tauri-plugin-"):]))

problems = 0
for crate, pkg in pairs:
    cv, nv = crates.get(crate), npm_version(pkg)
    if not cv or not nv:
        continue  # plugin used only on one side (e.g. Rust-only plugin)
    ok = major_minor(cv) == major_minor(nv)
    print(f"{'ok ' if ok else 'BAD'} {crate} {cv}  <->  {pkg} {nv}")
    problems += not ok

if problems:
    print(f"\n{problems} mismatch(es). Align the npm package (npm install {pkg}@~X.Y) "
          "or the crate so major.minor match.")
    sys.exit(1)
