package census

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procHits reads /proc (Linux) for processes holding an IOC lock file or
// carrying an IOC environment marker. Nothing is signalled.
func procHits(feed *IOCFeed) []HostHit {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []HostHit
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		base := filepath.Join("/proc", e.Name())
		cmd := cmdline(base)
		for _, in := range feed.Incidents {
			hit := ""
			if fds, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
				for _, fd := range fds {
					t, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
					if err == nil && contains(in.LockFiles, filepath.Base(t)) {
						hit = "process holding " + t
						break
					}
				}
			}
			if hit == "" && len(in.EnvMarkers) > 0 {
				if env, err := os.ReadFile(filepath.Join(base, "environ")); err == nil {
					for _, kv := range strings.Split(string(env), "\x00") {
						if contains(in.EnvMarkers, kv) {
							hit = "process with " + kv + " in its environment"
							break
						}
					}
				}
			}
			if hit != "" {
				cwd, _ := os.Readlink(filepath.Join(base, "cwd"))
				if cwd != "" {
					hit += ", cwd " + cwd
				}
				out = append(out, HostHit{What: hit, PID: pid, Cmd: cmd, IOC: in.ID})
			}
		}
	}
	return out
}

func cmdline(base string) string {
	b, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	if len(s) > 120 {
		s = s[:117] + "…"
	}
	return s
}
