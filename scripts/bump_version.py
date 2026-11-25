#!/usr/bin/env python3
"""Set the app version everywhere the release workflow checks it.

Usage: python scripts/bump_version.py 0.1.1

Updates alterchat-ui/package.json, alterchat-ui/package-lock.json,
alterchat-ui/src-tauri/tauri.conf.json and alterchat-ui/src-tauri/Cargo.toml,
and adds an empty section for the new version to CHANGELOG.md (moving the
current [Unreleased] notes under it). Cargo.lock is refreshed on the next build.
"""
import datetime
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
UI = ROOT / "alterchat-ui"


def set_json_version(path: pathlib.Path, version: str, lock: bool = False) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = version
    if lock and "" in data.get("packages", {}):
        data["packages"][""]["version"] = version
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?", sys.argv[1]):
        print(__doc__)
        return 2
    version = sys.argv[1]

    set_json_version(UI / "package.json", version)
    set_json_version(UI / "package-lock.json", version, lock=True)

    conf = UI / "src-tauri" / "tauri.conf.json"
    text = conf.read_text(encoding="utf-8")
    text, n = re.subn(r'("version"\s*:\s*")[^"]+(")', rf"\g<1>{version}\g<2>", text, count=1)
    assert n == 1, "version not found in tauri.conf.json"
    conf.write_text(text, encoding="utf-8")

    cargo = UI / "src-tauri" / "Cargo.toml"
    text = cargo.read_text(encoding="utf-8")
    text, n = re.subn(r'(?m)^version\s*=\s*"[^"]+"', f'version = "{version}"', text, count=1)
    assert n == 1, "version not found in Cargo.toml"
    cargo.write_text(text, encoding="utf-8")

    changelog = ROOT / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8")
    if f"## [{version}]" not in text:
        today = datetime.date.today().isoformat()
        text = text.replace("## [Unreleased]\n", f"## [Unreleased]\n\n## [{version}] - {today}\n", 1)
        changelog.write_text(text, encoding="utf-8")

    print(f"Version set to {version}. Next:")
    print(f'  git commit -am "Release v{version}" && git tag v{version} && git push origin main v{version}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
