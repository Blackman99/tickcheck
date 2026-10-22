package census

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Style paints text for a terminal (or not).
type Style struct{ On bool }

func (s Style) c(code, t string) string {
	if !s.On {
		return t
	}
	return "\x1b[" + code + "m" + t + "\x1b[0m"
}
func (s Style) Bad(t string) string     { return s.c("1;38;5;202", t) }
func (s Style) Suspect(t string) string { return s.c("1;38;5;178", t) }
func (s Style) Review(t string) string  { return s.c("38;5;110", t) }
func (s Style) OK(t string) string      { return s.c("38;5;72", t) }
func (s Style) Dim(t string) string     { return s.c("38;5;245", t) }
func (s Style) Bold(t string) string    { return s.c("1", t) }
func (s Style) Code(t string) string    { return s.c("38;5;223", t) }

func (s Style) V(v Verdict, t string) string {
	switch v {
	case Bad:
		return s.Bad(t)
	case Suspect:
		return s.Suspect(t)
	case Review:
		return s.Review(t)
	}
	return s.OK(t)
}

func pad(t string, n int) string {
	if l := len([]rune(t)); l < n {
		return t + strings.Repeat(" ", n-l)
	}
	return t
}

func human(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func when(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04 MST")
}

// Render writes the human report.
func Render(w io.Writer, r *Report, st Style, all bool) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f, a...) }
	envWord := "environments"
	if len(r.Envs) == 1 {
		envWord = "environment"
	}
	p("%s %s %d Python %s %s Python was never started %s %s\n",
		st.Bold("tickcheck"), st.Dim("·"), len(r.Envs), envWord, st.Dim("·"), st.Dim("·"), st.Dim(r.Took))
	if r.Demo {
		p("%s generated home %s %s nothing on this machine was read\n", st.Suspect("DEMO"), r.Home, st.Dim("—"))
	}
	p("\n")
	if len(r.Envs) == 0 {
		p("No Python environments found under %s.\n", strings.Join(tildeAll(r.Roots, r.Home), ", "))
		p("%s point it at them: %s\n", st.Dim("If yours live elsewhere,"), st.Code("tickcheck --root /path/to/envs"))
		p("%s %s\n", st.Dim("Containers:"), st.Code("docker export <id> | tar -x -C /tmp/rootfs && tickcheck --root /tmp/rootfs"))
		return
	}
	c := r.Counts
	p("  %s   %s   %s   %s   %s\n\n",
		st.Bad(fmt.Sprintf("BAD %d", c.Bad)), st.Suspect(fmt.Sprintf("SUSPECT %d", c.Suspect)),
		st.Review(fmt.Sprintf("REVIEW %d", c.Review)), st.OK(fmt.Sprintf("OK %d", c.OK)),
		st.Dim(fmt.Sprintf("startup hooks in %d %s", c.Envs, envWord)))

	var quiet []Env
	for _, e := range r.Envs {
		if e.Verdict == OK && !all {
			quiet = append(quiet, e)
			continue
		}
		renderEnv(w, r, e, st, all)
	}
	if len(quiet) > 0 {
		show := quiet
		if len(show) > 10 {
			show = show[:8]
		}
		for _, e := range show {
			n := len(e.Hooks)
			desc := "no startup hooks"
			if n > 0 {
				desc = fmt.Sprintf("%d known hook%s", n, plural(n))
			}
			p("%s %s %s\n", st.OK(pad("OK", 8)), pad(Tilde(e.Root, r.Home), 52), st.Dim(kindPy(e)+" · "+desc))
		}
		if len(show) < len(quiet) {
			p("%s %s\n", pad("", 8), st.Dim(fmt.Sprintf("+%d more clean environments (--all lists them)", len(quiet)-len(show))))
		}
		p("\n")
	}

	if len(r.Caches) > 0 {
		p("%s\n", st.Bold("package caches"))
		for _, h := range r.Caches {
			p("  %s %s\n    %s\n", st.Suspect("CACHED"), h.Detail, st.Dim(Tilde(h.Path, r.Home)))
		}
		p("  %s\n\n", st.Dim("the next install from cache brings it straight back: "+cacheFix(r.Caches)))
	}
	if len(r.Host) > 0 {
		p("%s\n", st.Bold("this host"))
		for _, h := range r.Host {
			if h.PID > 0 {
				p("  %s pid %d %s\n    %s\n", st.Bad("LIVE"), h.PID, h.What, st.Dim(h.Cmd))
			} else {
				p("  %s %s\n       %s\n", st.Bad("MARK"), h.What, st.Dim(Tilde(h.Path, r.Home)))
			}
		}
		p("\n")
	} else if r.ProcSkip != "" && r.Worst() >= Suspect {
		p("%s %s\n\n", st.Dim("process check:"), st.Dim(r.ProcSkip))
	}
	if len(r.Exposed) > 0 {
		p("%s %s\n", st.Bold("could have been read here"), st.Dim("(these exist; tickcheck did not open them)"))
		line := "  "
		for i, e := range r.Exposed {
			item := e
			if i < len(r.Exposed)-1 {
				item += "  "
			}
			if len(line)+len(item) > 96 {
				p("%s\n", strings.TrimRight(line, " "))
				line = "  "
			}
			line += item
		}
		p("%s\n\n", strings.TrimRight(line, " "))
	}
	renderNext(w, r, st)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func kindPy(e Env) string {
	if e.Python != "" {
		return e.Kind + " · python" + e.Python
	}
	return e.Kind
}

func tildeAll(ps []string, home string) []string {
	var out []string
	for _, p := range ps {
		out = append(out, Tilde(p, home))
	}
	return out
}

func renderEnv(w io.Writer, r *Report, e Env, st Style, all bool) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f, a...) }
	p("%s %s %s\n", st.V(e.Verdict, pad(e.Verdict.String(), 8)), st.Bold(pad(Tilde(e.Root, r.Home), 52)), st.Dim(kindPy(e)))
	for _, d := range e.BadDists {
		p("%s %s %s\n", pad("", 8), st.Bad("installed:"), d)
	}
	hooks := append([]Hook(nil), e.Hooks...)
	sort.SliceStable(hooks, func(i, j int) bool { return hooks[i].Verdict > hooks[j].Verdict })
	var okNames []string
	for _, h := range hooks {
		if h.Verdict == OK && !all {
			okNames = append(okNames, filepath.Base(h.File.Path))
			continue
		}
		renderHook(w, r, h, st)
	}
	if len(okNames) > 0 {
		p("%s %s\n", pad("", 8), st.Dim(fmt.Sprintf("+ %d known: %s", len(okNames), strings.Join(okNames, ", "))))
	}
	p("\n")
}

func renderHook(w io.Writer, r *Report, h Hook, st Style) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f, a...) }
	ind := pad("", 9)
	name := filepath.Base(h.File.Path)
	what := ""
	switch h.Kind {
	case "pth":
		l := h.Lines[0]
		if len(l) > 60 {
			l = l[:57] + "…"
		}
		what = "runs " + st.Code(l)
		if len(h.Lines) > 1 {
			what += st.Dim(fmt.Sprintf(" (+%d more lines)", len(h.Lines)-1))
		}
	default:
		what = st.Dim("imported on every start · " + human(h.File.Size))
	}
	p("%s%s %s %s\n", ind, st.V(h.Verdict, "▸"), st.V(h.Verdict, pad(name, 24)), what)
	sub := ind + "    "
	for _, l := range h.Loads {
		p("%s%s %s %s\n", sub, st.Dim("loads"), pad(filepath.Base(l.Path), 18), st.Dim(human(l.Size)+"  sha256 "+short(l.SHA256)+"…"))
	}
	if o := ownerOf(h); o != nil {
		inst := o.Installer
		if inst == "" {
			inst = "unknown installer"
		}
		rec := "RECORD hash ✓"
		if o.HashOK != nil && !*o.HashOK {
			rec = "RECORD hash ✗"
		} else if o.HashOK == nil {
			rec = "no RECORD hash"
		}
		p("%s%s %s %s\n", sub, st.Dim("owner"), o.Name+" "+o.Version, st.Dim("· "+inst+" · "+when(o.InstalledAt)+" · "+rec))
	} else {
		p("%s%s %s\n", sub, st.Dim("owner"), st.Dim("none (not in any RECORD)"))
	}
	mark := "·"
	if h.Verdict >= Suspect {
		mark = "✗"
	}
	for _, rs := range h.Reasons {
		p("%s%s %s\n", sub, st.V(h.Verdict, mark), rs)
	}
	for _, o := range h.Install {
		head := o.Harness
		if !o.When.IsZero() {
			head += " · " + when(o.When)
		}
		if o.Cwd != "" {
			head += " · " + Tilde(o.Cwd, r.Home)
		}
		p("%s%s %s %s %s\n", sub, st.Dim("installed by"), head, st.Dim("·"), st.Code(o.Command))
		p("%s%s %s\n", sub, pad("", 12), st.Dim(fmt.Sprintf("%s:%d", Tilde(o.File, r.Home), o.Line)))
	}
	if len(h.Residue) > 0 {
		var b []string
		for _, x := range h.Residue {
			b = append(b, filepath.Base(x))
		}
		p("%s%s %s\n", sub, st.Dim("compiled copies"), st.Dim(strings.Join(b, ", ")))
	}
}

func ownerOf(h Hook) *Owner {
	if h.File.Owner != nil {
		return h.File.Owner
	}
	for _, l := range h.Loads {
		if l.Owner != nil {
			return l.Owner
		}
	}
	return nil
}

func renderNext(w io.Writer, r *Report, st Style) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f, a...) }
	worst := r.Worst()
	demo := ""
	if r.Demo {
		demo = " --demo"
	}
	switch {
	case worst == Bad:
		items := Plan(r, Bad)
		p("%s\n", st.Bold("next"))
		p("  1. %s %s\n", st.Code(pad("tickcheck pull"+demo, 28)), st.Dim("move "+describeItems(items)+" aside; Python never starts"))
		step := 2
		for _, h := range r.Host {
			if h.PID > 0 {
				p("  %d. %s %s\n", step, st.Code(pad(fmt.Sprintf("kill %d", h.PID), 28)), st.Dim("the detached loader (check the command line above first)"))
				step++
				break
			}
		}
		fixes := map[string]bool{}
		var srcs []string
		for _, e := range r.Envs {
			for _, d := range e.BadDists {
				if i := strings.LastIndex(d, "("); i > 0 {
					id := strings.TrimSuffix(d[i+1:], ")")
					if in := r.Feed.Incident(id); in != nil && !fixes[id] {
						fixes[id] = true
						p("  %d. %s %s\n", step, pad("rebuild", 28), st.Dim(in.Fix))
						step++
						if len(in.Sources) > 0 {
							srcs = append(srcs, in.Sources[0])
						}
					}
				}
			}
		}
		p("  %d. %s %s\n", step, pad("rotate", 28), st.Dim("everything this machine could read (list above); pulling a hook doesn't un-steal anything"))
		for _, s := range srcs {
			p("     %s\n", st.Dim(s))
		}
	case worst == Suspect:
		p("%s\n", st.Bold("next"))
		p("  %s %s\n", st.Code(pad("tickcheck pull --suspect"+demo, 30)), st.Dim("move SUSPECT hooks aside (restore any time with tickcheck restore)"))
		p("  %s %s\n", pad("or read them first", 30), st.Dim("they're plain text; `less` is safe, `python` is not"))
	case worst == Review:
		p("%s %s\n", st.OK("Nothing matches a known compromise."), st.Dim("REVIEW = runs at startup and tickcheck can't vouch for it; read it with less, not python."))
	default:
		p("%s %s\n", st.OK("Every startup hook is a known pattern from its own package."), st.Dim("Re-run after the next install an agent makes."))
	}
}

func cacheFix(cs []CacheHit) string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cs {
		name := strings.Fields(c.Detail)[0]
		var cmd string
		switch c.Tool {
		case "uv":
			cmd = "uv cache clean " + name
		case "pip":
			cmd = "pip cache remove " + name + "  (from a clean env)"
		default:
			cmd = c.Tool + " cache clear --all ."
		}
		if !seen[cmd] {
			seen[cmd] = true
			out = append(out, cmd)
		}
	}
	return strings.Join(out, " · ")
}

func describeItems(items []PullItem) string {
	var pyc, other int
	for _, it := range items {
		if strings.HasSuffix(it.Orig, ".pyc") && strings.Contains(filepath.ToSlash(it.Orig), "/__pycache__/") {
			pyc++
		} else {
			other++
		}
	}
	s := fmt.Sprintf("%d file%s", other, plural(other))
	if pyc > 0 {
		s += fmt.Sprintf(" + %d compiled cop%s", pyc, map[bool]string{true: "y", false: "ies"}[pyc == 1])
	}
	return s
}
