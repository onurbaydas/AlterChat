"""Compare Tauri command parameters (Rust) with invoke() argument keys (TS).

Tauri 2 expects camelCase keys for snake_case Rust parameters by default.
Usage: python scripts/check_invokes.py <repo-root>   (runs in CI)
"""
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
src_tauri = root / "alterchat-ui" / "src-tauri" / "src"
src_ui = root / "alterchat-ui" / "src"

SKIP_TYPES = ("State<", "AppHandle", "Window", "Webview", "Request<", "ipc::Request", "Channel<")


def camel(s: str) -> str:
    parts = s.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


commands = {}
for f in src_tauri.rglob("*.rs"):
    text = f.read_text(encoding="utf-8")
    for m in re.finditer(r"#\[tauri::command[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*pub\s+(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\((.*?)\)\s*(?:->|\{)", text, re.S):
        name, params = m.group(1), m.group(2)
        rename_all = re.search(r'rename_all\s*=\s*"(\w+)"', m.group(0))
        args = []
        depth = 0
        cur = ""
        for ch in params:
            if ch in "<([":
                depth += 1
            elif ch in ">)]":
                depth -= 1
            if ch == "," and depth == 0:
                args.append(cur)
                cur = ""
            else:
                cur += ch
        if cur.strip():
            args.append(cur)
        keys = {}
        for a in args:
            if ":" not in a:
                continue
            pname, ptype = a.split(":", 1)
            pname = re.sub(r"^mut\s+", "", pname.strip())
            if any(t in ptype for t in SKIP_TYPES):
                continue
            optional = ptype.strip().startswith("Option<")
            key = pname if (rename_all and rename_all.group(1) == "snake_case") else camel(pname)
            keys[key] = optional
        commands[name] = (keys, f.relative_to(root))

problems = 0
for f in list(src_ui.rglob("*.tsx")) + list(src_ui.rglob("*.ts")):
    text = f.read_text(encoding="utf-8")
    for m in re.finditer(r'invoke(?:<[^(]*?>)?\(\s*"([\w:|]+)"\s*(,\s*\{)?', text):
        name = m.group(1)
        line = text.count("\n", 0, m.start()) + 1
        if name.startswith("plugin:"):
            continue
        if name not in commands:
            print(f"{f.name}:{line}: unknown command '{name}'")
            problems += 1
            continue
        expected, rsfile = commands[name]
        given = set()
        if m.group(2):
            i = m.end()
            depth = 1
            body = ""
            while i < len(text) and depth:
                c = text[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                if depth:
                    body += c
                i += 1
            # top-level keys only
            d = 0
            tok = ""
            for c in body + ",":
                if c in "{[(":
                    d += 1
                elif c in "}])":
                    d -= 1
                if c == "," and d == 0:
                    t = tok.strip()
                    if t:
                        k = re.match(r"^\.\.\.|^([A-Za-z_$][\w$]*)", t)
                        if k and k.group(1):
                            given.add(k.group(1))
                        elif t.startswith("..."):
                            given.add("...")
                    tok = ""
                else:
                    tok += c
        if "..." in given:
            continue
        missing = [k for k, opt in expected.items() if k not in given and not opt]
        extra = [k for k in given if k not in expected]
        if missing or extra:
            problems += 1
            print(f"{f.name}:{line}: {name}  missing={missing} unexpected={extra}  (rust: {rsfile})")

print(f"\n{len(commands)} commands, {problems} problem(s)")
sys.exit(1 if problems else 0)
