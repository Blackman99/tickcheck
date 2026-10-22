package census

import (
	"os"
	"path/filepath"
	"sort"
)

// Kinds of files the LiteLLM 1.107.0 stealer's modules target (per the
// SafeDep, Wiz, Chainguard and JFrog write-ups). tickcheck only checks that
// they exist; it never opens them.
var exposureGlobs = []string{
	".aws/credentials", ".aws/config", ".ssh/id_*", ".gnupg", ".kube/config", ".docker/config.json",
	".config/gcloud/application_default_credentials.json", ".azure", ".npmrc", ".pypirc",
	".git-credentials", ".config/gh/hosts.yml", ".codex/auth.json", ".claude/.credentials.json",
	".claude.json", ".local/share/opencode/auth.json", ".gemini/oauth_creds.json", ".cursor/mcp.json",
	".codeium/windsurf/mcp_config.json", ".config/github-copilot", ".aider.conf.yml",
	".cache/huggingface/token", ".config/Code/User/mcp.json", ".bash_history", ".zsh_history",
	".vault-token", ".terraform.d/credentials.tfrc.json",
}

func exposure(home string) []string {
	if home == "" {
		return nil
	}
	var out []string
	for _, g := range exposureGlobs {
		m, _ := filepath.Glob(filepath.Join(home, g))
		for _, p := range m {
			if filepath.Ext(p) == ".pub" {
				continue
			}
			if _, err := os.Lstat(p); err == nil {
				out = append(out, Tilde(p, home))
			}
		}
	}
	sort.Strings(out)
	return out
}
