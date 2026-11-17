package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

// resolveToolPath prefers ~/.aitools/bin, then PATH.
func resolveToolPath(tool string) string {
	home, _ := os.UserHomeDir()
	for _, c := range []string{
		filepath.Join(home, ".aitools", "bin", tool),
		filepath.Join(os.Getenv("HOME"), ".aitools", "bin", tool),
	} {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	if p, err := exec.LookPath(tool); err == nil {
		return p
	}
	return ""
}
