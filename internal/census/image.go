package census

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Blackman99/tickcheck/internal/oci"
)

// ImageInfo describes the scanned image in a report.
type ImageInfo struct {
	Ref      string    `json:"ref,omitempty"`
	Input    string    `json:"input"`
	Source   string    `json:"source"` // docker save | OCI layout | registry
	Digest   string    `json:"digest,omitempty"`
	Platform string    `json:"platform,omitempty"`
	Others   []string  `json:"other_platforms,omitempty"`
	Stats    oci.Stats `json:"layers_read"`
}

// ImageOptions selects the image to scan.
type ImageOptions = oci.Options

// ImagePath maps a path under the extraction dir back to the path inside the image.
func ImagePath(p, root string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(p)
	}
	if rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}

var (
	stdlibDirRE = regexp.MustCompile(`(^|/)[Pp]ython\d+\.\d+t?$`)
	metaDirRE   = regexp.MustCompile(`\.(dist|egg)-info$`)
)

// keepForCensus keeps only what the census reads: files at the top of a site
// dir, package metadata, the __init__ / __pycache__ of top-level packages a
// .pth may import, top-level files of a stdlib dir (sitecustomize, os.py),
// pyvenv.cfg, conda-meta, package caches and /tmp markers. Everything else in
// the image (often gigabytes) is streamed past without touching disk.
func keepForCensus(name string) bool {
	base := path.Base(name)
	if base == "pyvenv.cfg" {
		return true
	}
	if strings.HasPrefix(name, "tmp/") && strings.Count(name, "/") == 1 {
		return true
	}
	if strings.Contains(name, "/conda-meta/") {
		return true
	}
	for _, c := range []string{"/.cache/pip/", "/.cache/uv/", "/.cache/pypoetry/"} {
		if strings.Contains("/"+name, c) {
			return true
		}
	}
	segs := strings.Split(name, "/")
	for i, s := range segs {
		if s != "site-packages" && s != "dist-packages" {
			continue
		}
		rest := segs[i+1:]
		switch len(rest) {
		case 1:
			return true
		case 2:
			return metaDirRE.MatchString(rest[0]) || rest[0] == "__pycache__" || strings.HasPrefix(rest[1], "__init__.")
		case 3:
			// <pkg>/__pycache__/__init__.cpython-312.pyc
			return rest[1] == "__pycache__" && strings.HasPrefix(rest[2], "__init__.")
		}
		return false
	}
	dir := path.Dir(name)
	if stdlibDirRE.MatchString(dir) {
		return true // lib/python3.12/os.py, sitecustomize.py …
	}
	if stdlibDirRE.MatchString(path.Dir(dir)) && path.Base(dir) == "__pycache__" {
		return strings.HasPrefix(base, "sitecustomize.") || strings.HasPrefix(base, "usercustomize.")
	}
	return false
}

// RunImage reads an image (archive, OCI layout dir or public registry ref)
// without running it, merges its layers into a temp dir (only the files the
// census needs) and runs the same census on it. Paths in the report are paths
// inside the image.
func RunImage(arg string, o Options, io2 ImageOptions) (*Report, error) {
	start := time.Now()
	im, err := oci.Open(arg, io2)
	if err != nil {
		return nil, err
	}
	defer im.Close()
	tmp, err := os.MkdirTemp("", "tickcheck-image-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	st, err := oci.Extract(im, tmp, keepForCensus, 256<<20)
	if err != nil {
		return nil, err
	}
	o.Roots = []string{tmp}
	o.Home = filepath.Join(tmp, "root")
	o.TmpDirs = []string{filepath.Join(tmp, "tmp")}
	o.NoSystem, o.NoProcs, o.NoAttrib, o.Demo = true, true, true, false
	o.ImageRoot = tmp
	r, err := Run(o)
	if err != nil {
		return nil, err
	}
	rewritePaths(r, tmp)
	r.Home, r.Roots, r.ProcSkip, r.Exposed = "", []string{"/"}, "", nil
	r.Took = time.Since(start).Round(time.Millisecond).String()
	r.Image = &ImageInfo{Ref: im.Ref, Input: arg, Source: im.Source, Digest: im.Digest, Platform: im.Platform, Others: im.Others, Stats: st}
	return r, nil
}

func rewritePaths(r *Report, root string) {
	m := func(p string) string { return ImagePath(p, root) }
	fix := func(f *File) {
		f.Path = m(f.Path)
		f.Rel = filepath.ToSlash(f.Rel)
		if f.Owner != nil {
			f.Owner.DistInfo = m(f.Owner.DistInfo)
		}
	}
	for i := range r.Envs {
		e := &r.Envs[i]
		e.Root = m(e.Root)
		for j := range e.SiteDirs {
			e.SiteDirs[j] = m(e.SiteDirs[j])
		}
		for j := range e.Hooks {
			h := &e.Hooks[j]
			fix(&h.File)
			for k := range h.Loads {
				fix(&h.Loads[k])
			}
			for k := range h.Residue {
				h.Residue[k] = m(h.Residue[k])
			}
		}
	}
	for i := range r.Caches {
		r.Caches[i].Path = m(r.Caches[i].Path)
	}
	for i := range r.Host {
		r.Host[i].Path = m(r.Host[i].Path)
		r.Host[i].What = strings.ReplaceAll(r.Host[i].What, root, "")
	}
}

// imageLabel is the one-line description of the scanned image.
func imageLabel(im *ImageInfo) string {
	name := im.Ref
	if name == "" {
		name = im.Input
	}
	parts := []string{name}
	if im.Platform != "" {
		parts = append(parts, im.Platform)
	}
	if im.Digest != "" {
		parts = append(parts, strings.TrimPrefix(im.Digest, "sha256:")[:12])
	}
	parts = append(parts, fmt.Sprintf("%d layer%s from %s", im.Stats.Layers, plural(im.Stats.Layers), im.Source))
	return strings.Join(parts, " · ")
}

func renderImageHead(w io.Writer, r *Report, st Style) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f, a...) }
	p("%s %s\n", st.Dim("image"), imageLabel(r.Image))
	if len(r.Image.Others) > 0 {
		p("%s %s\n", st.Dim("also in this index:"), st.Dim(strings.Join(r.Image.Others, ", ")+" (pick one with --platform os/arch)"))
	}
	if n := r.Image.Stats.Symlinks; n > 0 {
		p("%s\n", st.Dim(fmt.Sprintf("note: %d symlinked file%s in Python dirs not followed (tickcheck never creates symlinks from an image)", n, plural(n))))
	}
}

func renderNextImage(w io.Writer, r *Report, st Style, worst Verdict) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f, a...) }
	switch worst {
	case Bad:
		p("%s\n", st.Bold("next"))
		step := 1
		seen := map[string]bool{}
		for _, e := range r.Envs {
			for _, d := range e.BadDists {
				if i := strings.LastIndex(d, "("); i > 0 {
					id := strings.TrimSuffix(d[i+1:], ")")
					if in := r.Feed.Incident(id); in != nil && !seen[id] {
						seen[id] = true
						p("  %d. %s %s\n", step, pad("rebuild", 10), st.Dim(in.Fix+", then push the new image and redeploy"))
						step++
					}
				}
			}
		}
		if step == 1 {
			p("  %d. %s %s\n", step, pad("rebuild", 10), st.Dim("from a base and packages that don't carry these hooks; push and redeploy"))
			step++
		}
		p("  %d. %s %s\n", step, pad("don't run", 10), st.Dim("this image, not even `docker run … pip list`: its python runs the hooks first"))
		step++
		p("  %d. %s %s\n", step, pad("rotate", 10), st.Dim("every secret a container from this image could reach (env vars, mounted files, cloud metadata)"))
	case Suspect:
		p("%s\n", st.Bold("next"))
		p("  %s %s\n", pad("read them", 10), st.Dim("they're plain text; copy them out with tar, never by starting the image's python"))
	case Review:
		p("%s %s\n", st.OK("Nothing matches a known compromise."), st.Dim("REVIEW = runs at startup and tickcheck can't vouch for it."))
	default:
		if r.Counts.Hooks == 0 {
			p("%s\n", st.OK(fmt.Sprintf("No startup hooks in %d environment%s.", r.Counts.Envs, plural(r.Counts.Envs))))
		} else {
			p("%s\n", st.OK("Every startup hook is a known pattern from its own package."))
		}
	}
}
