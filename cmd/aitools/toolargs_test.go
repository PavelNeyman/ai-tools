package main

import "testing"

func TestToolArgsGoPackagePattern(t *testing.T) {
	for _, tool := range []string{"deadcode", "errcheck", "govulncheck", "ineffassign", "staticcheck", "gosec", "nilaway"} {
		args := toolArgs(tool, "/tmp/repo")
		ok := false
		for _, a := range args {
			if a == "./..." {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("%s args %v: want ./...", tool, args)
		}
	}
	// shellcheck must not use ./...
	sh := toolArgs("shellcheck", "/tmp/repo")
	for _, a := range sh {
		if a == "./..." {
			t.Fatalf("shellcheck should not use ./...: %v", sh)
		}
	}
}
