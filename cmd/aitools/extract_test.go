package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractArchivePlainBinary(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "tool.tmp")
	dst := filepath.Join(dir, "mytool")
	payload := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x00, 0x00, 1, 2, 3}
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(src, dst, "mytool"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("mismatch")
	}
}
