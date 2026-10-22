package census

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxRead = 8 << 20

// record indexes every RECORD in a site dir: relative path -> owner.
type record struct {
	files map[string]*Owner
	dists []*Owner
}

func readRecords(site string) *record {
	r := &record{files: map[string]*Owner{}}
	ents, _ := os.ReadDir(site)
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() {
			continue
		}
		switch {
		case strings.HasSuffix(n, ".dist-info"):
			di := filepath.Join(site, n)
			o := &Owner{DistInfo: di}
			o.Name, o.Version = metaNameVersion(filepath.Join(di, "METADATA"), strings.TrimSuffix(n, ".dist-info"))
			if b, err := os.ReadFile(filepath.Join(di, "INSTALLER")); err == nil {
				o.Installer = strings.TrimSpace(string(b))
			}
			if st, err := os.Stat(filepath.Join(di, "RECORD")); err == nil {
				o.InstalledAt = st.ModTime()
			} else if st, err := os.Stat(di); err == nil {
				o.InstalledAt = st.ModTime()
			}
			r.dists = append(r.dists, o)
			f, err := os.Open(filepath.Join(di, "RECORD"))
			if err != nil {
				continue
			}
			cr := csv.NewReader(f)
			cr.FieldsPerRecord = -1
			cr.LazyQuotes = true
			for {
				row, err := cr.Read()
				if err != nil {
					break
				}
				if len(row) == 0 || row[0] == "" {
					continue
				}
				rel := filepath.Clean(filepath.FromSlash(row[0]))
				own := *o
				if len(row) > 1 && strings.HasPrefix(row[1], "sha256=") {
					if raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(row[1][7:], "=")); err == nil {
						own.RecordHash = hex.EncodeToString(raw)
					}
				}
				r.files[rel] = &own
			}
			f.Close()
		case strings.HasSuffix(n, ".egg-info"):
			di := filepath.Join(site, n)
			o := &Owner{DistInfo: di}
			o.Name, o.Version = metaNameVersion(filepath.Join(di, "PKG-INFO"), strings.TrimSuffix(n, ".egg-info"))
			if st, err := os.Stat(di); err == nil {
				o.InstalledAt = st.ModTime()
			}
			r.dists = append(r.dists, o)
			if b, err := os.ReadFile(filepath.Join(di, "installed-files.txt")); err == nil {
				for _, l := range strings.Split(string(b), "\n") {
					l = strings.TrimSpace(l)
					if l == "" {
						continue
					}
					rel, err := filepath.Rel(site, filepath.Join(di, filepath.FromSlash(l)))
					if err == nil {
						own := *o
						r.files[rel] = &own
					}
				}
			}
		}
	}
	return r
}

func metaNameVersion(meta, dirName string) (string, string) {
	name, ver := dirName, ""
	if i := strings.LastIndex(dirName, "-"); i > 0 {
		name, ver = dirName[:i], dirName[i+1:]
	}
	f, err := os.Open(meta)
	if err != nil {
		return name, ver
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			break
		}
		if v, ok := strings.CutPrefix(l, "Name: "); ok {
			name = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(l, "Version: "); ok {
			ver = strings.TrimSpace(v)
		}
	}
	return name, ver
}

// readFileInfo hashes a file and attaches its RECORD owner.
func readFileInfo(path, site string, rec *record) (File, []byte) {
	f := File{Path: path}
	if rel, err := filepath.Rel(site, path); err == nil {
		f.Rel = rel
	}
	fh, err := os.Open(path)
	if err != nil {
		return f, nil
	}
	defer fh.Close()
	h := sha256.New()
	var buf bytes.Buffer
	n, _ := io.Copy(io.MultiWriter(h, &limitWriter{&buf, maxRead}), fh)
	f.Size = n
	f.SHA256 = hex.EncodeToString(h.Sum(nil))
	if rec != nil {
		if o, ok := rec.files[filepath.Clean(f.Rel)]; ok {
			oc := *o
			if oc.RecordHash != "" {
				ok := oc.RecordHash == f.SHA256
				oc.HashOK = &ok
			}
			f.Owner = &oc
		}
	}
	return f, buf.Bytes()
}

type limitWriter struct {
	b *bytes.Buffer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

// pthExec reports whether a .pth line is executed by site.py:
// lines starting with "import" followed by a space or a tab.
func pthExec(line string) bool {
	return strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "import\t")
}

var (
	importRE   = regexp.MustCompile(`(?:^|;)\s*import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*)`)
	dunderRE   = regexp.MustCompile(`(?:__import__|import_module)\(\s*['"]([A-Za-z_][\w.]*)['"]`)
	fromRE     = regexp.MustCompile(`(?:^|;)\s*from\s+([A-Za-z_][\w.]*)\s+import`)
	stdlibSkip = map[string]bool{"os": true, "sys": true, "types": true, "importlib": true, "site": true, "warnings": true, "io": true, "re": true}
)

// pthModules lists the modules a .pth exec line imports.
func pthModules(line string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(m string) {
		m = strings.TrimSpace(m)
		top := strings.SplitN(m, ".", 2)[0]
		if top == "" || stdlibSkip[top] || seen[top] {
			return
		}
		seen[top] = true
		out = append(out, top)
	}
	for _, m := range importRE.FindAllStringSubmatch(line, -1) {
		for _, p := range strings.Split(m[1], ",") {
			add(strings.Fields(p)[0])
		}
	}
	for _, m := range dunderRE.FindAllStringSubmatch(line, -1) {
		add(m[1])
	}
	for _, m := range fromRE.FindAllStringSubmatch(line, -1) {
		add(m[1])
	}
	return out
}

// moduleFiles finds the file(s) Python would load for a top-level module in dir.
func moduleFiles(dir, mod string) []string {
	var out []string
	for _, c := range []string{mod + ".py", filepath.Join(mod, "__init__.py"), mod + ".pyc"} {
		p := filepath.Join(dir, c)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			out = append(out, p)
			return out
		}
	}
	for _, pat := range []string{mod + ".*.so", mod + ".so", mod + ".*.pyd", mod + ".pyd"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		if len(m) > 0 {
			return m[:1]
		}
	}
	return nil
}

// residue lists compiled copies Python leaves for a module in __pycache__.
func residue(dir, mod string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "__pycache__", mod+".*.pyc"))
	sort.Strings(m)
	return m
}

// scanSite lists every startup hook in one site dir (and sitecustomize in
// its stdlib parent, which is also on sys.path).
func scanSite(site string, feed *IOCFeed) ([]Hook, []string) {
	rec := readRecords(site)
	var hooks []Hook
	var badDists []string
	for _, d := range rec.dists {
		if id := feed.Dist(d.Name, d.Version); id != "" {
			badDists = append(badDists, d.Name+" "+d.Version+" ("+id+")")
		}
	}
	ents, _ := os.ReadDir(site)
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(n), ".pth") {
			continue
		}
		p := filepath.Join(site, n)
		f, body := readFileInfo(p, site, rec)
		h := Hook{Kind: "pth", File: f}
		var mods []string
		for _, raw := range strings.Split(string(body), "\n") {
			l := strings.TrimRight(raw, "\r")
			if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if pthExec(l) {
				h.Lines = append(h.Lines, l)
				mods = append(mods, pthModules(l)...)
			} else {
				h.PathLns++
			}
		}
		if len(h.Lines) == 0 {
			continue // path entries only: nothing runs
		}
		h.File.Signals = signals(body)
		seen := map[string]bool{}
		for _, m := range mods {
			if seen[m] {
				continue
			}
			seen[m] = true
			for _, mp := range moduleFiles(site, m) {
				mf, mb := readFileInfo(mp, site, rec)
				mf.Signals = signals(mb)
				h.Loads = append(h.Loads, mf)
			}
			h.Residue = append(h.Residue, residue(site, m)...)
		}
		hooks = append(hooks, h)
	}
	dirs := []string{site}
	parent := filepath.Dir(site)
	if pyVerRE.MatchString(filepath.Base(parent)) || strings.EqualFold(filepath.Base(parent), "Lib") {
		dirs = append(dirs, parent)
	}
	for _, dir := range dirs {
		var drec *record
		if dir == site {
			drec = rec
		}
		for _, mod := range []string{"sitecustomize", "usercustomize"} {
			for _, mp := range moduleFiles(dir, mod) {
				mf, mb := readFileInfo(mp, site, drec)
				if dir != site {
					mf.Rel = filepath.Join("..", filepath.Base(mp))
				}
				mf.Signals = signals(mb)
				h := Hook{Kind: mod, File: mf, Residue: residue(dir, mod)}
				hooks = append(hooks, h)
			}
		}
	}
	for i := range hooks {
		judge(&hooks[i], feed)
	}
	return hooks, badDists
}
