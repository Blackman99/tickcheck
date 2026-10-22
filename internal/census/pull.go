package census

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// PullItem is one file to move into quarantine.
type PullItem struct {
	Orig    string   `json:"original"`
	Stored  string   `json:"stored,omitempty"`
	SHA256  string   `json:"sha256"`
	Size    int64    `json:"size"`
	Mode    uint32   `json:"mode"`
	Verdict string   `json:"verdict"`
	Env     string   `json:"env"`
	Reasons []string `json:"reasons,omitempty"`
}

type Manifest struct {
	Created  time.Time  `json:"created"`
	Version  string     `json:"tickcheck_version"`
	Items    []PullItem `json:"items"`
	Restored bool       `json:"restored,omitempty"`
}

// Plan lists the files `pull` would move: every hook at or above min, the
// modules its .pth lines load, and their __pycache__ copies.
func Plan(r *Report, min Verdict) []PullItem {
	var out []PullItem
	seen := map[string]bool{}
	add := func(p, sha string, size int64, h Hook, env string) {
		if seen[p] {
			return
		}
		st, err := os.Lstat(p)
		if err != nil {
			return
		}
		seen[p] = true
		if sha == "" {
			sha = hashFile(p)
			size = st.Size()
		}
		out = append(out, PullItem{Orig: p, SHA256: sha, Size: size, Mode: uint32(st.Mode().Perm()), Verdict: h.Verdict.String(), Env: env, Reasons: h.Reasons})
	}
	for _, e := range r.Envs {
		for _, h := range e.Hooks {
			if h.Verdict < min {
				continue
			}
			add(h.File.Path, h.File.SHA256, h.File.Size, h, e.Root)
			for _, l := range h.Loads {
				add(l.Path, l.SHA256, l.Size, h, e.Root)
			}
			for _, rp := range h.Residue {
				add(rp, "", 0, h, e.Root)
			}
		}
	}
	return out
}

// Pull moves the planned files into dir/<stamp>/ and writes manifest.json.
// No interpreter is started; files are renamed (or copied then removed).
func Pull(items []PullItem, qdir, version string) (string, error) {
	if len(items) == 0 {
		return "", errors.New("nothing to pull")
	}
	stamp := time.Now().Format("20060102-150405")
	dest := filepath.Join(qdir, stamp)
	for i := 2; fileExists(dest); i++ {
		dest = filepath.Join(qdir, fmt.Sprintf("%s-%d", stamp, i))
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", err
	}
	m := Manifest{Created: time.Now(), Version: version}
	var firstErr error
	for i, it := range items {
		it.Stored = filepath.Join(dest, fmt.Sprintf("%02d-%s.quarantined", i+1, filepath.Base(it.Orig)))
		if err := move(it.Orig, it.Stored); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", it.Orig, err)
			}
			it.Stored = ""
		} else {
			_ = os.Chmod(it.Stored, 0o400)
		}
		m.Items = append(m.Items, it)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dest, "manifest.json"), b, 0o600); err != nil {
		return dest, err
	}
	return dest, firstErr
}

// Restore puts every file in a quarantine dir back where it came from.
func Restore(dir string) (*Manifest, error) {
	mp := filepath.Join(dir, "manifest.json")
	b, err := os.ReadFile(mp)
	if err != nil {
		return nil, fmt.Errorf("%s has no manifest.json; is it a tickcheck quarantine folder?", dir)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", mp, err)
	}
	var firstErr error
	for _, it := range m.Items {
		if it.Stored == "" || !fileExists(it.Stored) {
			continue // never moved, or already put back
		}
		if fileExists(it.Orig) {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s already exists; left the quarantined copy in place", it.Orig)
			}
			continue
		}
		_ = os.Chmod(it.Stored, 0o600)
		if err := move(it.Stored, it.Orig); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		_ = os.Chmod(it.Orig, os.FileMode(it.Mode))
	}
	if firstErr == nil {
		m.Restored = true
		nb, _ := json.MarshalIndent(m, "", "  ")
		_ = os.WriteFile(mp, nb, 0o600)
	}
	return &m, firstErr
}

func move(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		in.Close()
		return err
	}
	_, err = io.Copy(out, in)
	in.Close()
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}
