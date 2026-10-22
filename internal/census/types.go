// Package census finds every piece of code that runs when Python starts,
// in every Python environment it can see, without ever starting Python.
// Everything here reads files; nothing executes an interpreter, pip or a hook.
package census

import "time"

// Verdict ranks a hook. Order matters: higher is worse.
type Verdict int

const (
	OK Verdict = iota
	Review
	Suspect
	Bad
)

func (v Verdict) String() string {
	switch v {
	case Bad:
		return "BAD"
	case Suspect:
		return "SUSPECT"
	case Review:
		return "REVIEW"
	}
	return "OK"
}

func (v Verdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// Owner is the installed distribution whose RECORD lists a file.
type Owner struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Installer   string    `json:"installer,omitempty"`
	InstalledAt time.Time `json:"installed_at,omitempty"`
	DistInfo    string    `json:"dist_info"`
	RecordHash  string    `json:"record_sha256,omitempty"` // hex, from RECORD
	HashOK      *bool     `json:"record_hash_ok,omitempty"`
}

// File is one file on disk that takes part in a hook (the hook itself, or a
// module a .pth line imports).
type File struct {
	Path    string   `json:"path"`
	Rel     string   `json:"rel"`
	Size    int64    `json:"size"`
	SHA256  string   `json:"sha256"`
	Owner   *Owner   `json:"owner,omitempty"`
	Signals []string `json:"signals,omitempty"`
	IOC     string   `json:"ioc,omitempty"`
}

// Hook is one thing Python runs at startup in a site dir.
type Hook struct {
	Kind    string   `json:"kind"` // pth | sitecustomize | usercustomize
	File    File     `json:"file"`
	Lines   []string `json:"exec_lines,omitempty"` // executable .pth lines
	PathLns int      `json:"path_lines,omitempty"`
	Loads   []File   `json:"loads,omitempty"` // modules the exec lines import, found in this site dir
	Residue []string `json:"residue,omitempty"`
	Verdict Verdict  `json:"verdict"`
	Reasons []string `json:"reasons"`
	Known   string   `json:"known_as,omitempty"`
	Install []Origin `json:"installed_by,omitempty"`
}

// Origin is a transcript line that installed the hook's owning package.
type Origin struct {
	Harness string    `json:"harness"`
	File    string    `json:"file"`
	Line    int       `json:"line"`
	When    time.Time `json:"when,omitempty"`
	Cwd     string    `json:"cwd,omitempty"`
	Command string    `json:"command"`
}

// Env is one Python environment (a venv, a base install, a user site).
type Env struct {
	Root     string   `json:"root"`
	Kind     string   `json:"kind"`
	Python   string   `json:"python,omitempty"`
	SiteDirs []string `json:"site_dirs"`
	Hooks    []Hook   `json:"hooks"`
	BadDists []string `json:"bad_dists,omitempty"`
	Verdict  Verdict  `json:"verdict"`
}

// CacheHit is an IOC-listed distribution sitting in a package cache.
type CacheHit struct {
	Path   string `json:"path"`
	Tool   string `json:"tool"`
	IOC    string `json:"ioc"`
	Detail string `json:"detail"`
}

// HostHit is a host marker or live process from an IOC.
type HostHit struct {
	What string `json:"what"`
	Path string `json:"path,omitempty"`
	PID  int    `json:"pid,omitempty"`
	Cmd  string `json:"cmd,omitempty"`
	IOC  string `json:"ioc"`
}

// Report is a whole census.
type Report struct {
	Version    string     `json:"version"`
	ScannedAt  time.Time  `json:"scanned_at"`
	Took       string     `json:"took"`
	Home       string     `json:"home"`
	Roots      []string   `json:"roots"`
	Demo       bool       `json:"demo,omitempty"`
	Envs       []Env      `json:"envs"`
	Caches     []CacheHit `json:"caches,omitempty"`
	Host       []HostHit  `json:"host,omitempty"`
	ProcSkip   string     `json:"process_check_skipped,omitempty"`
	Exposed    []string   `json:"exposed_files,omitempty"`
	Counts     Counts     `json:"counts"`
	Unreadable int        `json:"unreadable_dirs"`
	Feed       *IOCFeed   `json:"-"`
}

type Counts struct {
	Envs    int `json:"envs"`
	Hooks   int `json:"hooks"`
	Bad     int `json:"bad"`
	Suspect int `json:"suspect"`
	Review  int `json:"review"`
	OK      int `json:"ok"`
}

// Worst is the worst verdict anywhere in the report (host and cache hits count as BAD).
func (r *Report) Worst() Verdict {
	w := OK
	for _, e := range r.Envs {
		if e.Verdict > w {
			w = e.Verdict
		}
	}
	if len(r.Caches) > 0 && w < Suspect {
		w = Suspect // a poisoned wheel in a cache is one `uv sync` away from an env
	}
	if len(r.Host) > 0 {
		w = Bad
	}
	return w
}
