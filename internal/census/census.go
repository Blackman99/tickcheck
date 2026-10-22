package census

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Run performs a census. It only reads files.
func Run(o Options) (*Report, error) {
	start := time.Now()
	feed, err := LoadIOC(o.ExtraIOC)
	if err != nil {
		return nil, err
	}
	home := o.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if o.MaxDepth == 0 {
		o.MaxDepth = 12
	}
	r := &Report{Version: o.Version, ScannedAt: start, Home: home, Demo: o.Demo, Feed: feed}
	roots := o.Roots
	if len(roots) == 0 {
		if home != "" {
			roots = append(roots, home)
		}
		if !o.NoSystem {
			roots = append(roots, systemRoots()...)
		}
	}
	seen := map[string]bool{}
	var sites, stdlibs []string
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			continue
		}
		r.Roots = append(r.Roots, abs)
		ss, sl := siteDirs(abs, o.MaxDepth, &r.Unreadable)
		stdlibs = append(stdlibs, sl...)
		for _, s := range ss {
			real := s
			if rs, err := filepath.EvalSymlinks(s); err == nil {
				real = rs
			}
			if !seen[real] {
				seen[real] = true
				sites = append(sites, s)
			}
		}
	}
	// stdlib dirs without their own site-packages (Debian's /usr/lib/python3.X,
	// whose packages live in /usr/lib/python3/dist-packages) still load sitecustomize.
	for _, sl := range stdlibs {
		if seen[filepath.Join(sl, "site-packages")] || fileExists(filepath.Join(sl, "site-packages")) {
			continue
		}
		hooks := scanStdlib(sl, feed)
		if len(hooks) == 0 {
			continue
		}
		e := Env{Root: sl, Kind: "stdlib", SiteDirs: []string{sl}, Hooks: hooks}
		if m := pyVerRE.FindStringSubmatch(sl); m != nil {
			e.Python = m[1]
		}
		for _, h := range hooks {
			if h.Verdict > e.Verdict {
				e.Verdict = h.Verdict
			}
		}
		r.Envs = append(r.Envs, e)
	}
	for _, e := range groupEnvs(sites, home) {
		for _, s := range e.SiteDirs {
			hooks, bad := scanSite(s, feed)
			e.Hooks = append(e.Hooks, hooks...)
			e.BadDists = append(e.BadDists, bad...)
		}
		for _, h := range e.Hooks {
			if h.Verdict > e.Verdict {
				e.Verdict = h.Verdict
			}
		}
		if len(e.BadDists) > 0 {
			e.Verdict = Bad
		}
		if e.Hooks == nil {
			e.Hooks = []Hook{} // "hooks": [] in JSON, not null
		}
		r.Envs = append(r.Envs, *e)
	}
	r.Caches = scanCaches(home, feed, roots)
	tmps := o.TmpDirs
	if len(tmps) == 0 {
		tmps = []string{os.TempDir()}
		if runtime.GOOS != "windows" && os.TempDir() != "/tmp" {
			tmps = append(tmps, "/tmp")
		}
	}
	r.Host = hostMarkers(tmps, feed)
	if o.NoProcs {
		r.ProcSkip = "skipped (--demo)"
	} else if runtime.GOOS != "linux" {
		r.ProcSkip = "only on Linux (reads /proc); on " + runtime.GOOS + " run: lsof /tmp/remote_code_loader.lock"
	} else {
		r.Host = append(r.Host, procHits(feed)...)
	}
	if !o.NoAttrib {
		attribute(r, home)
	}
	// with --root only (a rootfs, a CI workspace) the caller's own home is not the
	// scanned machine, so listing its credential files would point at the wrong box
	if r.Worst() == Bad && (len(o.Roots) == 0 || o.Home != "") {
		r.Exposed = exposure(home)
	}
	for _, e := range r.Envs {
		r.Counts.Envs++
		for _, h := range e.Hooks {
			r.Counts.Hooks++
			switch h.Verdict {
			case Bad:
				r.Counts.Bad++
			case Suspect:
				r.Counts.Suspect++
			case Review:
				r.Counts.Review++
			default:
				r.Counts.OK++
			}
		}
	}
	sort.SliceStable(r.Envs, func(i, j int) bool { return r.Envs[i].Verdict > r.Envs[j].Verdict })
	r.Took = time.Since(start).Round(time.Millisecond).String()
	return r, nil
}

// scanCaches looks for IOC-listed dists or wheels in pip/uv/poetry caches.
func scanCaches(home string, feed *IOCFeed, roots []string) []CacheHit {
	var dirs []struct{ p, tool string }
	add := func(p, tool string) {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			dirs = append(dirs, struct{ p, tool string }{p, tool})
		}
	}
	if home != "" {
		add(filepath.Join(home, ".cache", "uv"), "uv")
		add(filepath.Join(home, "Library", "Caches", "uv"), "uv")
		add(filepath.Join(home, "AppData", "Local", "uv", "cache"), "uv")
		add(filepath.Join(home, ".cache", "pip"), "pip")
		add(filepath.Join(home, "Library", "Caches", "pip"), "pip")
		add(filepath.Join(home, "AppData", "Local", "pip", "Cache"), "pip")
		add(filepath.Join(home, ".cache", "pypoetry"), "poetry")
		add(filepath.Join(home, "Library", "Caches", "pypoetry"), "poetry")
	}
	if v := os.Getenv("UV_CACHE_DIR"); v != "" {
		add(v, "uv")
	}
	var out []CacheHit
	for _, d := range dirs {
		_ = filepath.WalkDir(d.p, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			n := e.Name()
			if e.IsDir() && strings.HasSuffix(n, ".dist-info") {
				name, ver := metaNameVersion(filepath.Join(p, "METADATA"), strings.TrimSuffix(n, ".dist-info"))
				if id := feed.Dist(name, ver); id != "" {
					out = append(out, CacheHit{Path: p, Tool: d.tool, IOC: id, Detail: name + " " + ver + " unpacked in the " + d.tool + " cache"})
				}
				return fs.SkipDir
			}
			if !e.IsDir() && (strings.HasSuffix(n, ".whl") || strings.HasSuffix(n, ".tar.gz")) && feed.HasDist(strings.SplitN(n, "-", 2)[0]) {
				if sha := hashFile(p); sha != "" {
					if id, label := feed.File(sha); id != "" {
						out = append(out, CacheHit{Path: p, Tool: d.tool, IOC: id, Detail: label})
					}
				}
			}
			return nil
		})
	}
	return out
}

func hashFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hostMarkers globs each IOC's host markers in the temp dirs.
func hostMarkers(tmps []string, feed *IOCFeed) []HostHit {
	var out []HostHit
	seen := map[string]bool{}
	for _, in := range feed.Incidents {
		for _, t := range tmps {
			for _, g := range in.HostGlobs {
				m, _ := filepath.Glob(filepath.Join(t, g))
				for _, p := range m {
					if seen[p] {
						continue
					}
					seen[p] = true
					what := "host marker"
					if strings.HasPrefix(filepath.Base(p), ".pc_once_") {
						what = "exfil marker (written only after a successful upload)"
					} else if contains(in.LockFiles, filepath.Base(p)) {
						what = "loader lock file"
					}
					out = append(out, HostHit{What: what, Path: p, IOC: in.ID})
				}
			}
		}
	}
	return out
}
