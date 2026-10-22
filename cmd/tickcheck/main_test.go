package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	var o, e bytes.Buffer
	code := run(args, &o, &e, nil)
	return code, o.String(), e.String()
}

func TestDemoExitAndText(t *testing.T) {
	code, out, _ := runCLI(t, "--demo", "--no-color")
	if code != exitBad {
		t.Fatalf("exit %d want %d", code, exitBad)
	}
	for _, s := range []string{"Python was never started", "cook.pth", "litellm 1.107.0", "SUSPECT", "uv add litellm[proxy]", "tickcheck pull --demo", "uv cache clean litellm"} {
		if !strings.Contains(out, s) {
			t.Errorf("demo output missing %q", s)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("--no-color still painted")
	}
}

func TestDemoJSON(t *testing.T) {
	code, out, _ := runCLI(t, "--demo", "--json")
	if code != exitBad {
		t.Fatalf("exit %d", code)
	}
	var r struct {
		Counts struct{ Bad, Suspect, Review, OK int }
		Envs   []struct{ Verdict string }
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if r.Counts.Bad != 2 || r.Counts.Suspect != 1 || r.Counts.Review != 2 || len(r.Envs) != 7 || r.Envs[0].Verdict != "BAD" {
		t.Fatalf("counts %+v envs %d", r.Counts, len(r.Envs))
	}
}

func TestPullNeedsYesWithoutTTY(t *testing.T) {
	code, _, errs := runCLI(t, "pull", "--demo", "--no-color")
	if code != exitUsage || !strings.Contains(errs, "--yes") {
		t.Fatalf("code %d err %q", code, errs)
	}
}

func TestPullDemo(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	var o, e bytes.Buffer
	if c := run([]string{"--demo", "--json"}, &o, &e, nil); c != exitBad {
		t.Fatal(c)
	}
	o.Reset()
	if c := run([]string{"pull", "--demo", "--yes", "--no-color"}, &o, &e, nil); c != 0 {
		t.Fatalf("pull exit %d: %s", c, e.String())
	}
	if !strings.Contains(o.String(), "moved 5 files") || !strings.Contains(o.String(), "0 BAD hooks left") {
		t.Fatalf("pull output: %s", o.String())
	}
	o.Reset()
	if c := run([]string{"pull", "--demo", "--yes", "--no-color"}, &o, &e, nil); c != 0 || !strings.Contains(o.String(), "Nothing to pull") {
		t.Fatalf("second pull: %d %s", c, o.String())
	}
}

func TestUsageErrors(t *testing.T) {
	if c, _, e := runCLI(t, "pul"); c != exitUsage || !strings.Contains(e, "tickcheck pull") {
		t.Fatalf("typo: %d %q", c, e)
	}
	if c, _, e := runCLI(t, "./venv"); c != exitUsage || !strings.Contains(e, "unknown command") {
		t.Fatalf("path as command: %d %q", c, e)
	}
	if c, _, e := runCLI(t, "--frobnicate"); c != exitUsage || !strings.Contains(e, "--help") {
		t.Fatalf("bad flag: %d %q", c, e)
	}
	if c, _, e := runCLI(t, "restore"); c != exitUsage || !strings.Contains(e, "quarantine folder") {
		t.Fatalf("restore: %d %q", c, e)
	}
}

func TestEmptyRoot(t *testing.T) {
	d := t.TempDir()
	code, out, _ := runCLI(t, "--root", d, "--no-color")
	if code != 0 || !strings.Contains(out, "No Python environments found") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestVersion(t *testing.T) {
	_, out, _ := runCLI(t, "version")
	if strings.TrimSpace(out) != "tickcheck "+version {
		t.Fatal(out)
	}
	_ = os.Getenv
}
