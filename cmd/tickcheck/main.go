// Command tickcheck lists every piece of code that runs when Python starts,
// in every Python environment on the machine, without starting Python.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Blackman99/tickcheck/internal/census"
)

var version = "0.1.0"

const (
	exitOK      = 0
	exitErr     = 1
	exitSuspect = 3
	exitBad     = 4
	exitUsage   = 64
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type cli struct {
	roots, iocs             multi
	home, qdir              string
	noSystem, jsonOut, all  bool
	noColor, demo, noAttrib bool
	suspect, yes, dryRun    bool
	maxDepth                int
}

const usage = `tickcheck — what runs every time Python starts? Checked without starting Python.

usage:
  tickcheck [flags]                 census of startup hooks in every Python env it can find
  tickcheck pull [--suspect] [--yes] [--dry-run]
                                    move BAD (and SUSPECT) hooks into ~/.tickcheck/quarantine/
  tickcheck restore <dir>           put a quarantined set back
  tickcheck ioc                     print the built-in IOC feed (JSON; extend it with --ioc)
  tickcheck version

flags:
  --root DIR        scan only DIR (repeatable): a project, a CI workspace, an unpacked container rootfs
  --home DIR        home dir to walk (default: yours)
  --no-system       skip system-wide installs (/usr, Homebrew, /opt/conda, C:\Python…)
  --ioc FILE        extra IOC feed (repeatable); same format as 'tickcheck ioc'
  --all             also list OK hooks and clean environments
  --json            machine-readable report on stdout
  --no-color        plain text (NO_COLOR is honoured too)
  --no-attrib       don't search agent transcripts / shell history for who installed a package
  --max-depth N     directory depth to walk under each root (default 12)
  --demo            run on a generated home with a defanged LiteLLM 1.107.0 drop

exit codes: 0 nothing above REVIEW · 3 SUSPECT · 4 BAD · 64 usage · 1 error
docs: https://blackman99.github.io/tickcheck/docs/
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin)) }

func run(args []string, out, errw io.Writer, in *os.File) int {
	sub := "scan"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "version":
		fmt.Fprintf(out, "tickcheck %s\n", version)
		return exitOK
	case "help":
		fmt.Fprint(out, usage)
		return exitOK
	case "ioc":
		feed, err := census.LoadIOC(nil)
		if err != nil {
			fmt.Fprintln(errw, "tickcheck:", err)
			return exitErr
		}
		b, _ := json.MarshalIndent(feed, "", "  ")
		fmt.Fprintln(out, string(b))
		return exitOK
	case "scan", "pull", "restore":
	default:
		fmt.Fprintf(errw, "tickcheck: unknown command %q\n", sub)
		if s := suggest(sub); s != "" {
			fmt.Fprintf(errw, "Did you mean `tickcheck %s`?\n", s)
		}
		fmt.Fprintln(errw, "Run `tickcheck --help` for usage.")
		return exitUsage
	}
	var c cli
	fs := flag.NewFlagSet("tickcheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&c.roots, "root", "")
	fs.Var(&c.iocs, "ioc", "")
	fs.StringVar(&c.home, "home", "", "")
	fs.StringVar(&c.qdir, "quarantine-dir", "", "")
	fs.BoolVar(&c.noSystem, "no-system", false, "")
	fs.BoolVar(&c.jsonOut, "json", false, "")
	fs.BoolVar(&c.all, "all", false, "")
	fs.BoolVar(&c.noColor, "no-color", false, "")
	fs.BoolVar(&c.demo, "demo", false, "")
	fs.BoolVar(&c.noAttrib, "no-attrib", false, "")
	fs.BoolVar(&c.suspect, "suspect", false, "")
	fs.BoolVar(&c.yes, "yes", false, "")
	fs.BoolVar(&c.yes, "y", false, "")
	fs.BoolVar(&c.dryRun, "dry-run", false, "")
	fs.IntVar(&c.maxDepth, "max-depth", 12, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, usage)
			return exitOK
		}
		fmt.Fprintf(errw, "tickcheck: %v\nRun `tickcheck --help` for usage.\n", err)
		return exitUsage
	}
	st := census.Style{On: colorOn(out, c.noColor || c.jsonOut)}
	if sub == "restore" {
		if fs.NArg() != 1 {
			fmt.Fprintln(errw, "tickcheck: restore needs the quarantine folder, e.g. tickcheck restore ~/.tickcheck/quarantine/20261022-104512")
			return exitUsage
		}
		m, err := census.Restore(fs.Arg(0))
		if m != nil {
			n := 0
			for _, it := range m.Items {
				if it.Stored != "" && !fileExists(it.Stored) {
					n++
					fmt.Fprintf(out, "  %s %s\n", st.Dim("restored"), it.Orig)
				}
			}
			fmt.Fprintf(out, "%d of %d files back in place.\n", n, len(m.Items))
		}
		if err != nil {
			fmt.Fprintln(errw, "tickcheck:", err)
			return exitErr
		}
		return exitOK
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(errw, "tickcheck: unexpected argument %q (to scan a folder use --root %s)\n", fs.Arg(0), fs.Arg(0))
		return exitUsage
	}
	opts := census.Options{Home: c.home, Roots: c.roots, NoSystem: c.noSystem, ExtraIOC: c.iocs, MaxDepth: c.maxDepth, Version: version, NoAttrib: c.noAttrib}
	if c.demo {
		dir := filepath.Join(os.TempDir(), "tickcheck-demo")
		home, tmp := filepath.Join(dir, "home", "dana"), filepath.Join(dir, "tmp")
		if sub == "scan" || !fileExists(home) {
			var err error
			if home, tmp, err = census.MakeDemo(dir); err != nil {
				fmt.Fprintln(errw, "tickcheck: building the demo home:", err)
				return exitErr
			}
		}
		opts.Home, opts.Roots, opts.NoSystem, opts.TmpDirs, opts.NoProcs, opts.Demo = home, nil, true, []string{tmp}, true, true
	}
	r, err := census.Run(opts)
	if err != nil {
		fmt.Fprintln(errw, "tickcheck:", err)
		return exitUsage
	}
	if sub == "pull" {
		return pull(c, opts, r, out, errw, in, st)
	}
	if c.jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	} else {
		census.Render(out, r, st, c.all)
	}
	switch r.Worst() {
	case census.Bad:
		return exitBad
	case census.Suspect:
		return exitSuspect
	}
	return exitOK
}

func pull(c cli, opts census.Options, r *census.Report, out, errw io.Writer, in *os.File, st census.Style) int {
	min := census.Bad
	if c.suspect {
		min = census.Suspect
	}
	items := census.Plan(r, min)
	p := func(f string, a ...any) { fmt.Fprintf(out, f, a...) }
	if len(items) == 0 {
		what := "BAD"
		if c.suspect {
			what = "BAD or SUSPECT"
		}
		p("Nothing to pull: no %s startup hooks in %d environments.\n", what, r.Counts.Envs)
		if !c.suspect && r.Counts.Suspect > 0 {
			p("%s %d SUSPECT hook%s: %s\n", st.Dim("There are"), r.Counts.Suspect, plural(r.Counts.Suspect), st.Code("tickcheck pull --suspect"))
		}
		return exitOK
	}
	envs := map[string][]string{}
	var order []string
	for _, it := range items {
		if _, ok := envs[it.Env]; !ok {
			order = append(order, it.Env)
		}
		envs[it.Env] = append(envs[it.Env], filepath.Base(it.Orig))
	}
	qdir := c.qdir
	if qdir == "" {
		qdir = filepath.Join(r.Home, ".tickcheck", "quarantine")
	}
	p("%s %s %d file%s from %d environment%s %s Python was never started\n\n", st.Bold("tickcheck pull"), st.Dim("·"), len(items), plural(len(items)), len(order), plural(len(order)), st.Dim("·"))
	for _, e := range order {
		p("  %s\n    %s\n", census.Tilde(e, r.Home), strings.Join(envs[e], "  "))
	}
	p("\n")
	if c.dryRun {
		p("%s nothing moved. Without --dry-run they go to %s\n", st.Dim("dry run:"), census.Tilde(qdir, r.Home))
		return exitOK
	}
	if !c.yes {
		if !isTTY(in) {
			fmt.Fprintln(errw, "tickcheck: no terminal to confirm on; pass --yes to move them")
			return exitUsage
		}
		p("Move them to %s? [y/N] ", census.Tilde(qdir, r.Home))
		ans, _ := bufio.NewReader(in).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			p("Nothing moved.\n")
			return exitOK
		}
	}
	dest, err := census.Pull(items, qdir, version)
	if dest != "" {
		p("%s %d file%s → %s\n", st.OK("moved"), len(items), plural(len(items)), census.Tilde(dest, r.Home)+string(filepath.Separator))
		p("%s\n", st.Dim("  manifest.json lists every file and its sha256; `tickcheck restore "+census.Tilde(dest, r.Home)+"` puts them back"))
	}
	if err != nil {
		fmt.Fprintln(errw, "tickcheck:", err)
		return exitErr
	}
	r2, err := census.Run(opts)
	if err == nil {
		left := 0
		for _, e := range r2.Envs {
			for _, h := range e.Hooks {
				if h.Verdict >= min {
					left++
				}
			}
		}
		p("\n%s %d %s hook%s left in %d environments.\n", st.Dim("re-check:"), left, min.String(), plural(left), r2.Counts.Envs)
		for _, e := range r2.Envs {
			for _, d := range e.BadDists {
				p("%s %s is still installed in %s: rebuild that env, don't run its pip.\n", st.Suspect("note:"), d, census.Tilde(e.Root, r.Home))
			}
		}
		if r.Worst() == census.Bad {
			p("%s\n", st.Dim("Pulling stops the next run. If it ever ran with network access, rotate what this machine could read."))
		}
	}
	return exitOK
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func suggest(s string) string {
	for _, c := range []string{"pull", "restore", "ioc", "version", "scan"} {
		if strings.HasPrefix(c, s) || strings.HasPrefix(s, c) || lev(s, c) <= 2 {
			if c == "scan" {
				return "(no command needed: just tickcheck)"
			}
			return c
		}
	}
	return ""
}

func lev(a, b string) int {
	d := make([]int, len(b)+1)
	for j := range d {
		d[j] = j
	}
	for i := 1; i <= len(a); i++ {
		prev := d[0]
		d[0] = i
		for j := 1; j <= len(b); j++ {
			t := d[j]
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[j] = min3(d[j]+1, d[j-1]+1, prev+cost)
			prev = t
		}
	}
	return d[len(b)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

func isTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func colorOn(w io.Writer, off bool) bool {
	if off || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	f, ok := w.(*os.File)
	return ok && isTTY(f)
}

func fileExists(p string) bool { _, err := os.Lstat(p); return err == nil }
