package census

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	installRE = regexp.MustCompile(`(?i)\b(uv\s+pip\s+install|uv\s+add|uv\s+tool\s+install|uvx|pipx\s+install|pip3?\s+install|python3?\s+-m\s+pip\s+install|poetry\s+add|conda\s+install|mamba\s+install)\b[^"\\\n\r]{0,160}`)
	tsRE      = regexp.MustCompile(`"timestamp"\s*:\s*"([0-9T:.\-+Z]+)"`)
	cwdRE     = regexp.MustCompile(`\\?"(?:cwd|workdir)\\?"\s*:\s*\\?"([^"\\]+)`)
	zshTS     = regexp.MustCompile(`^: (\d+):\d+;`)
)

type transcriptSource struct {
	harness string
	dir     string
	ext     string
}

// attribute finds which agent session (or shell) installed the packages that
// own BAD / SUSPECT hooks. It searches transcripts and shell history as text.
func attribute(r *Report, home string) {
	want := map[string]bool{}
	for _, e := range r.Envs {
		for _, h := range e.Hooks {
			if h.Verdict < Suspect || h.File.Owner == nil {
				continue
			}
			want[normName(h.File.Owner.Name)] = true
		}
		for _, d := range e.BadDists {
			want[normName(strings.Fields(d)[0])] = true
		}
	}
	if len(want) == 0 || home == "" {
		return
	}
	srcs := []transcriptSource{
		{"Claude Code", filepath.Join(home, ".claude", "projects"), ".jsonl"},
		{"Codex", filepath.Join(home, ".codex", "sessions"), ".jsonl"},
		{"Codex", filepath.Join(home, ".codex", "archived_sessions"), ".jsonl"},
		{"OpenCode", filepath.Join(home, ".local", "share", "opencode", "storage"), ".json"},
		{"Gemini CLI", filepath.Join(home, ".gemini", "tmp"), ".json"},
	}
	found := map[string][]Origin{}
	for _, s := range srcs {
		_ = filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, s.ext) {
				return nil
			}
			scanTranscript(p, s.harness, want, found)
			return nil
		})
	}
	for _, hf := range []string{".bash_history", ".zsh_history", filepath.Join(".local", "share", "fish", "fish_history")} {
		scanTranscript(filepath.Join(home, hf), "shell history", want, found)
	}
	for pkg := range found {
		sort.Slice(found[pkg], func(i, j int) bool { return found[pkg][i].When.After(found[pkg][j].When) })
	}
	for ei := range r.Envs {
		for hi := range r.Envs[ei].Hooks {
			h := &r.Envs[ei].Hooks[hi]
			if h.Verdict < Suspect || h.File.Owner == nil {
				continue
			}
			o := found[normName(h.File.Owner.Name)]
			if len(o) > 3 {
				o = o[:3]
			}
			h.Install = o
		}
	}
}

func scanTranscript(p, harness string, want map[string]bool, found map[string][]Origin) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	n := 0
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			n++
			if bytes.Contains(line, []byte("install")) || bytes.Contains(line, []byte(" add")) || bytes.Contains(line, []byte("uvx")) {
				matchLine(line, p, n, harness, want, found)
			}
		}
		if err != nil {
			return
		}
	}
}

func matchLine(line []byte, p string, n int, harness string, want map[string]bool, found map[string][]Origin) {
	s := string(line)
	for _, m := range installRE.FindAllString(s, -1) {
		cmd := strings.TrimSpace(m)
		for _, tok := range strings.Fields(cmd) {
			tok = strings.Trim(tok, `'"`)
			name := tok
			if i := strings.IndexAny(tok, "=<>!~[;&|"); i > 0 {
				name = tok[:i]
			}
			if !want[normName(name)] {
				continue
			}
			o := Origin{Harness: harness, File: p, Line: n, Command: trimCmd(cmd)}
			if t := tsRE.FindStringSubmatch(s); t != nil {
				o.When, _ = time.Parse(time.RFC3339Nano, t[1])
			} else if z := zshTS.FindStringSubmatch(s); z != nil {
				var sec int64
				for _, c := range z[1] {
					sec = sec*10 + int64(c-'0')
				}
				o.When = time.Unix(sec, 0)
			}
			if c := cwdRE.FindStringSubmatch(s); c != nil {
				o.Cwd = c[1]
			}
			key := normName(name)
			found[key] = append(found[key], o)
			return
		}
	}
}

func trimCmd(c string) string {
	for _, cut := range []string{" && ", " ; ", " | ", "\\n", "`"} {
		if i := strings.Index(c, cut); i > 0 {
			c = c[:i]
		}
	}
	if len(c) > 90 {
		c = c[:87] + "…"
	}
	return c
}
