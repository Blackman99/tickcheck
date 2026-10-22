package census

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type sig struct {
	name string
	re   *regexp.Regexp
}

// Static content signals. Nothing is decoded or run; these are text matches.
var sigs = []sig{
	{"encoded blob → exec", regexp.MustCompile(`(?s)(b64decode|a85decode|b32decode|zlib\.decompress|lzma\.decompress|marshal\.loads|bytes\.fromhex|codecs\.decode).{0,400}\b(exec|eval|compile)\s*\(|\b(exec|eval)\s*\(\s*(__import__\(['"](zlib|base64|marshal)|zlib|base64|marshal)`)},
	{"spawns processes", regexp.MustCompile(`\bsubprocess\.|\bos\.(system|popen|exec[lv]p?e?|spawn[lv]p?e?)\s*\(|\bpty\.spawn`)},
	{"network", regexp.MustCompile(`\burllib\.request\b|\burlopen\s*\(|\brequests\.(get|post|put|Session)\b|\bhttp\.client\b|\bsocket\.(socket|create_connection)\b|\bhttpx\.(get|post|Client)|\baiohttp\.ClientSession`)},
	{"detaches (fork/setsid)", regexp.MustCompile(`\bos\.fork\s*\(|\bos\.setsid\s*\(|\bdaemon\s*=\s*True|\bfcntl\.flock\b`)},
	{"reads credentials", regexp.MustCompile(`\.aws/credentials|\.ssh/id_|\.kube/config|auth\.json|\.credentials\.json|\.git-credentials|\.npmrc|\.pypirc|Login Data|cookies\.sqlite|\.gnupg`)},
}

func signals(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	var out []string
	for i, g := range sigs {
		if g.re.MatchString(s) {
			out = append(out, g.name)
		}
		if i == 0 && longRun(b, 1500) {
			out = append(out, "long encoded literal")
		}
	}
	return out
}

type known struct {
	label  string
	name   *regexp.Regexp // file name
	body   *regexp.Regexp // content must match (exec lines or module text)
	owners []string       // allowed owner dists (normalised); empty = must be unowned tool file or any
	anyOwn bool           // any owner is fine
	unown  bool           // may be unowned (written by venv tools, distros)
	nameOw bool           // owner name must appear in the file name
}

var knownHooks = []known{
	{label: "setuptools distutils shim", name: regexp.MustCompile(`^distutils-precedence\.pth$`), body: regexp.MustCompile(`_distutils_hack`), owners: []string{"setuptools"}},
	{label: "virtualenv / uv venv patch", name: regexp.MustCompile(`^_virtualenv\.pth$`), body: regexp.MustCompile(`^import _virtualenv\s*$`), unown: true, anyOwn: true},
	{label: "editable install (PEP 660)", name: regexp.MustCompile(`^__editable__[._].*\.pth$`), body: regexp.MustCompile(`__editable__`), anyOwn: true, nameOw: true},
	{label: "namespace package (-nspkg)", name: regexp.MustCompile(`-nspkg\.pth$`), body: regexp.MustCompile(`^import sys, types, os;`), anyOwn: true, nameOw: true},
	{label: "pywin32 bootstrap", name: regexp.MustCompile(`^pywin32\.pth$`), body: regexp.MustCompile(`pywin32_bootstrap`), owners: []string{"pywin32"}},
	{label: "coverage subprocess measurement", name: regexp.MustCompile(`coverage.*\.pth$`), body: regexp.MustCompile(`coverage`), owners: []string{"coverage", "pytest-cov"}},
	{label: "Debian/Ubuntu apport hook", name: regexp.MustCompile(`^sitecustomize\.py$`), body: regexp.MustCompile(`apport_python_hook`), unown: true},
	{label: "Homebrew site path", name: regexp.MustCompile(`^sitecustomize\.py$`), body: regexp.MustCompile(`(?i)homebrew`), unown: true},
	{label: "uv/virtualenv support module", name: regexp.MustCompile(`^_virtualenv\.py$`), body: regexp.MustCompile(`virtualenv`), unown: true, anyOwn: true},
}

// related reports whether the hook name plausibly belongs to the owner dist.
func related(hookBase, owner string) bool {
	h := normName(strings.TrimSuffix(strings.TrimSuffix(hookBase, filepath.Ext(hookBase)), "-nspkg"))
	o := normName(owner)
	if o == "" || h == "" {
		return false
	}
	if strings.Contains(h, o) || strings.Contains(o, h) {
		return true
	}
	for _, t := range strings.Split(o, "-") {
		if len(t) >= 4 && strings.Contains(h, t) {
			return true
		}
	}
	return false
}

func matchKnown(h *Hook) string {
	base := filepath.Base(h.File.Path)
	body := strings.Join(h.Lines, "\n")
	for _, k := range knownHooks {
		if !k.name.MatchString(base) {
			continue
		}
		text := body
		if h.Kind != "pth" {
			text = "" // module text checked through signals; body regex on module below
		}
		if h.Kind == "pth" && !k.body.MatchString(text) {
			continue
		}
		o := h.File.Owner
		switch {
		case o == nil && !k.unown:
			continue
		case o != nil && len(k.owners) > 0 && !contains(k.owners, normName(o.Name)):
			continue
		case o != nil && k.nameOw && !related(base, o.Name):
			continue
		}
		return k.label
	}
	return ""
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// judge sets the verdict and reasons for one hook.
func judge(h *Hook, feed *IOCFeed) {
	h.Verdict = OK
	var rs []string
	up := func(v Verdict, why string) {
		if v > h.Verdict {
			h.Verdict = v
		}
		rs = append(rs, why)
	}
	files := append([]*File{&h.File}, ptrs(h.Loads)...)
	iocHit := false
	distIOC := map[string][]string{} // "name version (id)" -> files
	var distOrder []string
	for _, f := range files {
		if id, label := feed.File(f.SHA256); id != "" {
			f.IOC = id
			iocHit = true
			up(Bad, fmt.Sprintf("%s is byte-identical to %s in %s", filepath.Base(f.Path), label, id))
		}
		if f.Owner != nil {
			if id := feed.Dist(f.Owner.Name, f.Owner.Version); id != "" {
				f.IOC = id
				iocHit = true
				k := fmt.Sprintf("%s %s is listed in %s", f.Owner.Name, f.Owner.Version, id)
				if _, ok := distIOC[k]; !ok {
					distOrder = append(distOrder, k)
				}
				distIOC[k] = append(distIOC[k], filepath.Base(f.Path))
			}
		}
	}
	for _, k := range distOrder {
		h.Verdict = Bad
		rs = append(rs, k+" (it installed "+strings.Join(distIOC[k], ", ")+")")
	}
	h.Known = matchKnown(h)
	if h.Known != "" && h.Kind != "pth" {
		// module hooks: the known body regex must match the module text too
		h.Known = knownModule(h)
	}
	var orphans, orphanSig []string
	for _, f := range files {
		base := filepath.Base(f.Path)
		if f.Owner == nil {
			if h.Known == "" {
				orphans = append(orphans, base)
				orphanSig = append(orphanSig, f.Signals...)
			}
			continue
		}
		if f.Owner.HashOK != nil && !*f.Owner.HashOK {
			up(Suspect, fmt.Sprintf("%s changed after %s %s installed it (RECORD sha256 %s…, on disk %s…)", base, f.Owner.Name, f.Owner.Version, short(f.Owner.RecordHash), short(f.SHA256)))
		}
		if h.Known == "" && !iocHit && !related(base, f.Owner.Name) && f == &h.File {
			up(Suspect, fmt.Sprintf("%s %s installs a startup hook named %s", f.Owner.Name, f.Owner.Version, base))
		}
	}
	if len(orphans) > 0 {
		verb := "is"
		if len(orphans) > 1 {
			verb = "are"
		}
		msg := strings.Join(orphans, " and ") + " " + verb + " not in any installed package's RECORD"
		if len(orphanSig) > 0 {
			up(Suspect, msg+"; "+strings.Join(dedupe(orphanSig), ", "))
		} else {
			up(Review, msg)
		}
	}
	for _, f := range files {
		if len(f.Signals) > 0 && (f.Owner != nil || h.Known != "") {
			up(Suspect, filepath.Base(f.Path)+": "+strings.Join(f.Signals, ", "))
		}
	}
	if h.Known != "" && h.Verdict == OK {
		rs = append(rs, h.Known)
	}
	if h.Verdict == OK && h.Known == "" && len(rs) == 0 {
		o := h.File.Owner
		h.Verdict = Review
		if o != nil {
			rs = append(rs, fmt.Sprintf("belongs to %s %s, intact; not a pattern tickcheck knows", o.Name, o.Version))
		}
	}
	h.Reasons = dedupe(rs)
}

func knownModule(h *Hook) string {
	// a module hook is "known" only if its owner/location rule matched and
	// it carries no payload signals; the label then stands.
	if len(h.File.Signals) > 0 {
		return ""
	}
	for _, k := range knownHooks {
		if k.name.MatchString(filepath.Base(h.File.Path)) && k.unown && h.File.Owner == nil {
			if b := readHead(h.File.Path); k.body.Match(b) {
				return k.label
			}
		}
	}
	return ""
}

// longRun reports a run of at least n base64/hex-alphabet bytes.
func longRun(b []byte, n int) bool {
	run := 0
	for _, c := range b {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' || c == '_' || c == '-' {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func readHead(p string) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	b := make([]byte, 64<<10)
	n, _ := io.ReadFull(f, b)
	return b[:n]
}

func ptrs(fs []File) []*File {
	out := make([]*File, len(fs))
	for i := range fs {
		out[i] = &fs[i]
	}
	return out
}

func short(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
