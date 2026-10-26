package census

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func demoRun(t *testing.T) (*Report, string) {
	t.Helper()
	dir := t.TempDir()
	home, tmp, err := MakeDemo(filepath.Join(dir, "demo"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Run(Options{Home: home, NoSystem: true, TmpDirs: []string{tmp}, NoProcs: true, Demo: true})
	if err != nil {
		t.Fatal(err)
	}
	return r, home
}

func envBy(r *Report, suffix string) *Env {
	for i := range r.Envs {
		if strings.HasSuffix(filepath.ToSlash(r.Envs[i].Root), suffix) {
			return &r.Envs[i]
		}
	}
	return nil
}

func hookBy(e *Env, name string) *Hook {
	for i := range e.Hooks {
		if filepath.Base(e.Hooks[i].File.Path) == name {
			return &e.Hooks[i]
		}
	}
	return nil
}

func TestPthExecRule(t *testing.T) {
	cases := map[string]bool{
		"import cook":            true,
		"import\tcook":           true,
		"importcook":             false,
		" import cook":           false, // leading space: site.py treats it as a path
		"/opt/lib/site":          false,
		"# import cook":          false,
		"import os; os.getpid()": true,
	}
	for l, want := range cases {
		if got := pthExec(l); got != want {
			t.Errorf("pthExec(%q)=%v want %v", l, got, want)
		}
	}
}

func TestPthModules(t *testing.T) {
	got := pthModules("import os; var = 'X'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); ")
	if strings.Join(got, ",") != "_distutils_hack" {
		t.Fatalf("got %v", got)
	}
	got = pthModules("import cook, evil.sub; from sneaky import x")
	if strings.Join(got, ",") != "cook,evil,sneaky" {
		t.Fatalf("got %v", got)
	}
}

func TestCookPthIsTheRealBytes(t *testing.T) {
	h := sha256.Sum256([]byte(demoCookPth))
	feed, _ := LoadIOC(nil)
	if id, _ := feed.File(hex.EncodeToString(h[:])); id != "litellm-2026-10-21" {
		t.Fatalf("12-byte cook.pth should match the published sha256, got %q", id)
	}
}

func TestDemoVerdicts(t *testing.T) {
	r, _ := demoRun(t)
	if r.Counts.Envs != 7 {
		t.Fatalf("envs=%d want 7", r.Counts.Envs)
	}
	want := map[string]Verdict{
		"proj/agent-proxy/.venv":                          Bad,
		"work/scraper/.claude/worktrees/agent-7c1e/.venv": Suspect,
		"miniforge3/envs/rag":                             Review,
		".local/lib/python3.12/site-packages":             Review,
		".pyenv/versions/3.11.9":                          OK,
		".local/share/uv/tools/llm":                       OK,
		".local/pipx/venvs/httpie":                        OK,
	}
	for suf, v := range want {
		e := envBy(r, suf)
		if e == nil {
			t.Fatalf("env %s not found", suf)
		}
		if e.Verdict != v {
			t.Errorf("%s verdict %v want %v (%+v)", suf, e.Verdict, v, e.Hooks)
		}
	}
	px := envBy(r, "proj/agent-proxy/.venv")
	cook := hookBy(px, "cook.pth")
	if cook == nil || cook.Verdict != Bad || len(cook.Loads) != 1 || filepath.Base(cook.Loads[0].Path) != "cook.py" {
		t.Fatalf("cook.pth hook wrong: %+v", cook)
	}
	if len(cook.Install) == 0 || cook.Install[0].Harness != "Claude Code" || !strings.Contains(cook.Install[0].Command, "uv add litellm") {
		t.Fatalf("attribution missing: %+v", cook.Install)
	}
	if len(cook.Residue) != 1 {
		t.Fatalf("residue %v", cook.Residue)
	}
	for _, n := range []string{"distutils-precedence.pth", "_virtualenv.pth"} {
		if h := hookBy(px, n); h == nil || h.Verdict != OK {
			t.Errorf("%s should be OK: %+v", n, h)
		}
	}
	if hookBy(envBy(r, "pipx/venvs/httpie"), "httpie.pth") != nil {
		t.Error("path-only .pth must not count as a hook")
	}
	sus := hookBy(envBy(r, "agent-7c1e/.venv"), "fastjsonx_rt.pth")
	if sus == nil || len(sus.Install) == 0 || sus.Install[0].Harness != "Codex" {
		t.Fatalf("codex attribution: %+v", sus)
	}
	if len(r.Caches) != 1 || len(r.Host) != 2 {
		t.Fatalf("caches=%d host=%d", len(r.Caches), len(r.Host))
	}
	if r.Worst() != Bad || len(r.Exposed) != 5 {
		t.Fatalf("worst=%v exposed=%v", r.Worst(), r.Exposed)
	}
}

func TestRecordMismatchIsSuspect(t *testing.T) {
	dir := t.TempDir()
	site := filepath.Join(dir, "venv", "lib", "python3.12", "site-packages")
	os.MkdirAll(site, 0o755)
	os.WriteFile(filepath.Join(dir, "venv", "pyvenv.cfg"), []byte("home=/usr/bin\n"), 0o644)
	writeDist(site, "setuptools", "80.0.0", "pip", []demoFile{{"distutils-precedence.pth", distutilsPth}}, testTime)
	// tamper after install
	os.WriteFile(filepath.Join(site, "distutils-precedence.pth"), []byte("import os; __import__('_distutils_hack'); import evil\n"), 0o644)
	r, err := Run(Options{Roots: []string{dir}, NoProcs: true, NoAttrib: true, TmpDirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	h := hookBy(&r.Envs[0], "distutils-precedence.pth")
	if h == nil || h.Verdict != Suspect || !strings.Contains(strings.Join(h.Reasons, " "), "changed after setuptools") {
		t.Fatalf("tampered known hook must be SUSPECT: %+v", h)
	}
}

func TestKnownNameWithPayloadIsSuspect(t *testing.T) {
	dir := t.TempDir()
	site := filepath.Join(dir, "v", "lib", "python3.12", "site-packages")
	os.MkdirAll(site, 0o755)
	os.WriteFile(filepath.Join(dir, "v", "pyvenv.cfg"), []byte(""), 0o644)
	os.WriteFile(filepath.Join(site, "_virtualenv.pth"), []byte("import _virtualenv\n"), 0o644)
	os.WriteFile(filepath.Join(site, "_virtualenv.py"), []byte("import subprocess\nsubprocess.Popen(['curl','https://x.invalid'])\n"), 0o644)
	r, _ := Run(Options{Roots: []string{dir}, NoProcs: true, NoAttrib: true, TmpDirs: []string{dir}})
	h := hookBy(&r.Envs[0], "_virtualenv.pth")
	if h == nil || h.Verdict != Suspect {
		t.Fatalf("known name hiding a payload must be SUSPECT: %+v", h)
	}
}

func TestPullRestoreRoundTrip(t *testing.T) {
	r, home := demoRun(t)
	items := Plan(r, Bad)
	if len(items) != 5 {
		t.Fatalf("plan %d items, want 5 (cook.pth cook.py sitecustomize.py + 2 pyc): %+v", len(items), items)
	}
	q := filepath.Join(home, ".tickcheck", "quarantine")
	dest, err := Pull(items, q, "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if fileExists(it.Orig) {
			t.Fatalf("%s still there", it.Orig)
		}
	}
	r2, _ := Run(Options{Home: home, NoSystem: true, NoProcs: true, NoAttrib: true, TmpDirs: []string{t.TempDir()}})
	for _, e := range r2.Envs {
		for _, h := range e.Hooks {
			if h.Verdict == Bad {
				t.Fatalf("BAD hook left after pull: %s", h.File.Path)
			}
		}
	}
	if _, err := Restore(dest); err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if !fileExists(it.Orig) {
			t.Fatalf("%s not restored", it.Orig)
		}
	}
	if _, err := Restore(dest); err != nil {
		t.Fatalf("second restore should be a no-op: %v", err)
	}
}

func TestEmptyHome(t *testing.T) {
	r, err := Run(Options{Home: t.TempDir(), NoSystem: true, NoProcs: true, TmpDirs: []string{t.TempDir()}})
	if err != nil || len(r.Envs) != 0 || r.Worst() != OK {
		t.Fatalf("empty home: %v %+v", err, r)
	}
}

func TestBadIOCFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	os.WriteFile(p, []byte(`{"nope":1}`), 0o644)
	if _, err := LoadIOC([]string{p}); err == nil || !strings.Contains(err.Error(), "no incidents") {
		t.Fatalf("want a clear error, got %v", err)
	}
}

func TestRelated(t *testing.T) {
	if related("cook.pth", "litellm") {
		t.Error("cook is not litellm")
	}
	if !related("zope.interface-7.1.0-py3.11-nspkg.pth", "zope.interface") || !related("pytest-cov.pth", "pytest-cov") {
		t.Error("should be related")
	}
}

func TestRootOnlyScopesNextStepsAndSkipsHostExposure(t *testing.T) {
	root := t.TempDir()
	sp := filepath.Join(root, "usr", "local", "lib", "python3.12", "site-packages")
	if err := os.MkdirAll(sp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sp, "cook.pth"), []byte("import cook\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Run(Options{Roots: []string{root}, NoSystem: true, NoProcs: true, NoAttrib: true, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Worst() != Bad {
		t.Fatalf("want BAD, got %v", r.Worst())
	}
	if len(r.Exposed) != 0 {
		t.Fatalf("a --root scan must not list the caller's own credential files: %v", r.Exposed)
	}
	r.ScopeArgs = " --root " + root
	var b strings.Builder
	Render(&b, r, Style{}, false)
	if !strings.Contains(b.String(), "tickcheck pull --root "+root) {
		t.Fatalf("next step should repeat --root:\n%s", b.String())
	}
}

// The win_amd64 wheel ships cook.pth with a CRLF line ending, so its hash
// differs from the Linux/macOS one. Both must be recognised without an owner dist.
func TestCookPthWindowsVariant(t *testing.T) {
	h := sha256.Sum256([]byte("import cook\r\n"))
	feed, _ := LoadIOC(nil)
	if id, _ := feed.File(hex.EncodeToString(h[:])); id != "litellm-2026-10-21" {
		t.Fatalf("CRLF cook.pth should match the published Windows sha256, got %q", id)
	}
	for _, sum := range []string{
		"03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea",
		"b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465",
	} {
		if id, _ := feed.File(sum); id != "litellm-2026-10-21" {
			t.Errorf("Windows payload %s… missing from feed", sum[:8])
		}
	}
}
