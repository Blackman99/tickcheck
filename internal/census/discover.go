package census

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Options controls where the census looks.
type Options struct {
	Home        string   // home dir to walk; "" = the user's home
	Roots       []string // explicit roots; when set, only these are walked
	NoSystem    bool     // skip system-wide Python installs
	TmpDirs     []string // where to look for host markers; "" = os.TempDir() and /tmp
	NoProcs     bool     // skip the /proc check
	NoAttrib    bool     // skip transcript search
	ExtraIOC    []string
	MaxDepth    int
	Version     string
	Demo        bool
	ExposureFor []string // override for tests
}

// pruned directory names: big trees that never hold a Python env.
var pruneNames = map[string]bool{
	"node_modules": true, ".git": true, ".hg": true, ".svn": true, ".npm": true,
	".cargo": true, ".rustup": true, ".gradle": true, ".m2": true, ".Trash": true,
	"__pycache__": true, ".tox-cache": true, "huggingface": true, "torch": true,
	"google-chrome": true, "chromium": true, "mozilla": true, "Mail": true,
	"Photos Library.photoslibrary": true, ".docker": true, "proc": true,
}

var pyVerRE = regexp.MustCompile(`(?i)python(\d+\.\d+t?)`)

// siteDirs walks root and returns every site-packages / dist-packages dir.
func siteDirs(root string, maxDepth int, unreadable *int) []string {
	var out []string
	root = filepath.Clean(root)
	base := strings.Count(root, string(filepath.Separator))
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() || p == root {
				*unreadable++
			}
			return fs.SkipDir
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if p != root && pruneNames[name] {
			return fs.SkipDir
		}
		if name == "site-packages" || name == "dist-packages" {
			out = append(out, p)
			return fs.SkipDir
		}
		if strings.Count(p, string(filepath.Separator))-base >= maxDepth {
			return fs.SkipDir
		}
		return nil
	})
	return out
}

// systemRoots are base installs outside the home dir.
func systemRoots() []string {
	var c []string
	switch runtime.GOOS {
	case "windows":
		for _, v := range []string{"LOCALAPPDATA", "APPDATA", "ProgramFiles", "ProgramData"} {
			if b := os.Getenv(v); b != "" {
				c = append(c, filepath.Join(b, "Programs", "Python"), filepath.Join(b, "Python"),
					filepath.Join(b, "miniconda3"), filepath.Join(b, "anaconda3"))
			}
		}
		m, _ := filepath.Glob(`C:\Python*`)
		c = append(c, m...)
	default:
		g := []string{"/usr/lib/python3*", "/usr/lib64/python3*", "/usr/local/lib/python3*",
			"/opt/homebrew/lib/python3*", "/opt/homebrew/Cellar/python@*", "/usr/local/Cellar/python@*",
			"/Library/Frameworks/Python.framework/Versions", "/opt/conda", "/opt/venv", "/opt/*/venv",
			"/opt/*/.venv", "/app", "/srv/*/.venv", "/usr/local/python*"}
		for _, p := range g {
			m, _ := filepath.Glob(p)
			c = append(c, m...)
		}
	}
	var out []string
	for _, p := range c {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// groupEnvs maps site dirs to environments.
func groupEnvs(sites []string, home string) []*Env {
	byRoot := map[string]*Env{}
	var order []string
	for _, s := range sites {
		root, kind := envRootKind(s, home)
		e := byRoot[root]
		if e == nil {
			e = &Env{Root: root, Kind: kind}
			if m := pyVerRE.FindStringSubmatch(s); m != nil {
				e.Python = m[1]
			}
			byRoot[root] = e
			order = append(order, root)
		}
		e.SiteDirs = append(e.SiteDirs, s)
	}
	sort.Strings(order)
	var out []*Env
	for _, r := range order {
		out = append(out, byRoot[r])
	}
	return out
}

func envRootKind(site, home string) (string, string) {
	// .../lib/python3.12/site-packages -> 3 up; .../Lib/site-packages -> 2 up
	parent := filepath.Dir(site)
	root := parent
	if strings.EqualFold(filepath.Base(parent), "lib") {
		root = filepath.Dir(parent)
	} else if pyVerRE.MatchString(filepath.Base(parent)) {
		root = filepath.Dir(filepath.Dir(parent))
		if strings.EqualFold(filepath.Base(root), "lib") || strings.EqualFold(filepath.Base(root), "lib64") {
			root = filepath.Dir(root)
		}
	}
	slash := filepath.ToSlash(site)
	hasCfg := fileExists(filepath.Join(root, "pyvenv.cfg"))
	switch {
	case strings.Contains(slash, "/.local/lib/python") || strings.Contains(slash, "/Library/Python/") && !hasCfg || strings.Contains(slash, "/AppData/Roaming/Python/"):
		return site, "user site"
	case strings.Contains(slash, "/pipx/venvs/"):
		return root, "pipx"
	case strings.Contains(slash, "/uv/tools/"):
		return root, "uv tool"
	case strings.Contains(slash, "/uv/python/"):
		return root, "uv python"
	case strings.Contains(slash, "/.pyenv/versions/"):
		if hasCfg {
			return root, "pyenv venv"
		}
		return root, "pyenv"
	case strings.Contains(slash, "/pre-commit/"):
		return root, "pre-commit"
	case fileExists(filepath.Join(root, "conda-meta")):
		return root, "conda"
	case hasCfg:
		if strings.Contains(slash, "/.claude/worktrees/") || strings.Contains(slash, "/.codex/worktrees/") || strings.Contains(slash, "/worktrees/agent-") {
			return root, "venv · agent worktree"
		}
		return root, "venv"
	case strings.HasPrefix(slash, "/opt/homebrew/") || strings.Contains(slash, "/Cellar/"):
		return root, "homebrew"
	case strings.HasPrefix(slash, "/usr/") || strings.HasPrefix(slash, "/Library/"):
		return root, "system"
	}
	return root, "python"
}

func fileExists(p string) bool { _, err := os.Lstat(p); return err == nil }

// tilde shortens a path under home for display.
func Tilde(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+string(filepath.Separator))) {
		return "~" + p[len(home):]
	}
	return p
}
