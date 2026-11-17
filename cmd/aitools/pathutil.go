package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// shellcheckArgs collects *.sh / *.bash under root for shellcheck JSON output.
func shellcheckArgs(root string) []string {
	args := []string{"-f=json", "-x"}
	var files []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".aitools" {
				return filepath.SkipDir
			}
			return nil
		}
		n := strings.ToLower(info.Name())
		if strings.HasSuffix(n, ".sh") || strings.HasSuffix(n, ".bash") {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = path
			}
			files = append(files, rel)
		}
		return nil
	})
	if len(files) == 0 {
		// No scripts: still run with empty target so tool exits cleanly with empty JSON array.
		return append(args, "/dev/null")
	}
	if len(files) > 200 {
		files = files[:200]
	}
	return append(args, files...)
}
