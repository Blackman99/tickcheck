#!/usr/bin/env bash
# End-to-end against real Python: real venvs, a real `pip install` of a wheel
# that drops startup hooks through .data/purelib (the LiteLLM 1.107.0 trick),
# real virtualenv and editable installs. Asserts that tickcheck finds the
# hooks, judges them, never starts Python itself, and that pull/restore work.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
PY=${PYTHON:-python3}
BIN=bin; [ "${OS:-}" = Windows_NT ] && BIN=Scripts
say() { printf '\n== %s\n' "$*"; }

go build -o "$W/tickcheck" "$here/cmd/tickcheck"
TC="$W/tickcheck"

say "venvs: stdlib venv + setuptools, virtualenv, editable install"
$PY -m venv "$W/envs/plain"
"$W/envs/plain/$BIN/python" -m pip install -q --disable-pip-version-check setuptools virtualenv
"$W/envs/plain/$BIN/python" -m virtualenv -q "$W/envs/venv2"
mkdir -p "$W/src/mytool/mytool"
printf '[build-system]\nrequires=["setuptools>=64"]\nbuild-backend="setuptools.build_meta"\n[project]\nname="mytool"\nversion="0.3.0"\n' > "$W/src/mytool/pyproject.toml"
echo "" > "$W/src/mytool/mytool/__init__.py"
"$W/envs/venv2/$BIN/python" -m pip install -q --disable-pip-version-check -e "$W/src/mytool"

say "build a wheel whose .data/purelib drops cook.pth + an unrelated hook"
MARK="$W/hook-ran"
$PY - "$W/hookdemo-0.1.0-py3-none-any.whl" "$MARK" <<'PY'
import sys, zipfile, hashlib, base64, zlib
out, mark = sys.argv[1], sys.argv[2]
files = {
  "hookdemo/__init__.py": "",
  "hookdemo-0.1.0.data/purelib/cook.pth": "import cook\n",
  "hookdemo-0.1.0.data/purelib/cook.py": "open(%r, 'a').write('cook ran\\n')\n" % mark,
  "hookdemo-0.1.0.data/purelib/zzz_boot.pth": "import zzz_boot\n",
  "hookdemo-0.1.0.data/purelib/zzz_boot.py": "import base64, zlib\nexec(zlib.decompress(base64.b64decode(%r)))\n" % base64.b64encode(zlib.compress(b"pass")),
  "hookdemo-0.1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: hookdemo\nVersion: 0.1.0\n",
  "hookdemo-0.1.0.dist-info/WHEEL": "Wheel-Version: 1.0\nGenerator: tickcheck-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
}
rec = []
with zipfile.ZipFile(out, "w") as z:
    for n, b in files.items():
        z.writestr(n, b)
        h = base64.urlsafe_b64encode(hashlib.sha256(b.encode()).digest()).rstrip(b"=").decode()
        rec.append(f"{n},sha256={h},{len(b.encode())}")
    rec.append("hookdemo-0.1.0.dist-info/RECORD,,")
    z.writestr("hookdemo-0.1.0.dist-info/RECORD", "\n".join(rec) + "\n")
PY
"$W/envs/plain/$BIN/python" -m pip install -q --disable-pip-version-check --no-index "$W/hookdemo-0.1.0-py3-none-any.whl"
rm -f "$MARK"   # pip itself started Python after the install? start clean either way

say "tickcheck must never start Python: decoy python/pip on PATH"
DECOY="$W/decoy-ran"
mkdir -p "$W/decoy"
for n in python python3 pip pip3 uv; do printf '#!/bin/sh\necho decoy >> %s\nexit 1\n' "$DECOY" > "$W/decoy/$n"; chmod +x "$W/decoy/$n"; done

set +e
PATH="$W/decoy:$PATH" "$TC" --root "$W/envs" --json --no-attrib > "$W/report.json"
code=$?
PATH="$W/decoy:$PATH" "$TC" --root "$W/envs" --no-color --no-attrib > "$W/report.txt"
set -e
cat "$W/report.txt"
[ "$code" = 4 ] || { echo "want exit 4 (BAD), got $code"; exit 1; }
[ ! -e "$MARK" ] || { echo "a hook ran during the scan"; exit 1; }
[ ! -e "$DECOY" ] || { echo "tickcheck started python/pip"; exit 1; }

$PY - "$W/report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
hooks = {}
for e in r["envs"]:
    for h in e["hooks"]:
        hooks[(e["root"].rsplit("/", 1)[-1], h["file"]["path"].replace("\\", "/").rsplit("/", 1)[-1])] = (h, e)
def want(env, name, verdict, owner=None):
    h, e = hooks[(env, name)]
    assert h["verdict"] == verdict, (env, name, h["verdict"], h["reasons"])
    if owner:
        o = h["file"].get("owner") or {}
        assert o.get("name") == owner, (name, o)
        assert o.get("record_hash_ok") is True, (name, o)
    print(f"ok  {env:8} {name:40} {verdict:8} {'; '.join(h['reasons'])[:90]}")
want("plain", "cook.pth", "BAD", "hookdemo")
want("plain", "zzz_boot.pth", "SUSPECT", "hookdemo")
want("plain", "distutils-precedence.pth", "OK", "setuptools")
if ("venv2", "_virtualenv.pth") in hooks:  # older virtualenv/uv only
    want("venv2", "_virtualenv.pth", "OK")
edit = [k for k in hooks if k[0] == "venv2" and k[1].startswith("__editable__")]
assert edit, ("editable install hook not found", sorted(k for k in hooks if k[0] == "venv2"))
want("venv2", edit[0][1], "OK", "mytool")
PY

say "the hook really runs on a normal Python start (what tickcheck avoided)"
"$W/envs/plain/$BIN/python" -c pass
grep -q "cook ran" "$MARK" && echo "ok  starting the env's python ran cook.pth"
rm -f "$MARK"

say "pull, then Python starts clean; restore puts it back"
"$TC" pull --root "$W/envs" --yes --no-color --no-attrib --quarantine-dir "$W/q" | tee "$W/pull.txt"
"$W/envs/plain/$BIN/python" -c pass
[ ! -e "$MARK" ] || { echo "hook still ran after pull"; exit 1; }
echo "ok  no hook ran after pull"
qd=$(ls -d "$W"/q/*/ | head -1)
"$TC" restore "$qd" --no-color
"$W/envs/plain/$BIN/python" -c pass
grep -q "cook ran" "$MARK" && echo "ok  restore put the hook back"
echo; echo "real-python e2e: all checks passed"
