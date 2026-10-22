package census

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

//go:embed ioc.json
var builtinIOC []byte

// Incident is one published compromise: what files, dists and host traces it leaves.
type Incident struct {
	ID         string            `json:"id"`
	Title      string            `json:"title"`
	Sources    []string          `json:"sources"`
	Dists      []DistIOC         `json:"dists"`
	Fix        string            `json:"fix"`
	FileSHA256 map[string]string `json:"file_sha256"`
	HostGlobs  []string          `json:"host_globs"`
	LockFiles  []string          `json:"lock_files"`
	EnvMarkers []string          `json:"env_markers"`
}

type DistIOC struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

type IOCFeed struct {
	Schema    int        `json:"schema"`
	Incidents []Incident `json:"incidents"`
}

// LoadIOC returns the built-in feed plus any extra feed files.
func LoadIOC(extra []string) (*IOCFeed, error) {
	var f IOCFeed
	if err := json.Unmarshal(builtinIOC, &f); err != nil {
		return nil, err
	}
	for _, p := range extra {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("--ioc %s: %w", p, err)
		}
		var g IOCFeed
		if err := json.Unmarshal(b, &g); err != nil {
			return nil, fmt.Errorf("--ioc %s is not a tickcheck IOC feed (%v); see docs/#ioc", p, err)
		}
		if len(g.Incidents) == 0 {
			return nil, fmt.Errorf("--ioc %s has no incidents; see docs/#ioc for the format", p)
		}
		f.Incidents = append(f.Incidents, g.Incidents...)
	}
	return &f, nil
}

// File returns the incident and label for a file hash.
func (f *IOCFeed) File(sha string) (string, string) {
	for _, in := range f.Incidents {
		if l, ok := in.FileSHA256[sha]; ok {
			return in.ID, l
		}
	}
	return "", ""
}

// Dist returns the incident that lists name==version.
func (f *IOCFeed) Dist(name, version string) string {
	n := normName(name)
	for _, in := range f.Incidents {
		for _, d := range in.Dists {
			if normName(d.Name) != n {
				continue
			}
			for _, v := range d.Versions {
				if v == version {
					return in.ID
				}
			}
		}
	}
	return ""
}

// normName is PEP 503 name normalisation.
func normName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	dash := false
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' {
			if !dash {
				b.WriteByte('-')
			}
			dash = true
			continue
		}
		dash = false
		b.WriteRune(r)
	}
	return b.String()
}

// HasDist reports whether any incident names this distribution.
func (f *IOCFeed) HasDist(name string) bool {
	n := normName(name)
	for _, in := range f.Incidents {
		for _, d := range in.Dists {
			if normName(d.Name) == n {
				return true
			}
		}
	}
	return false
}

// Incident returns an incident by id.
func (f *IOCFeed) Incident(id string) *Incident {
	for i := range f.Incidents {
		if f.Incidents[i].ID == id {
			return &f.Incidents[i]
		}
	}
	return nil
}
