package main

import "testing"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte("hello netductor review\nsecrets=no")
	enc, err := encryptBytes(plain, "test-key-please")
	if err != nil {
		t.Fatal(err)
	}
	out, err := decryptBytes(enc, "test-key-please")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plain) {
		t.Fatalf("mismatch %q vs %q", out, plain)
	}
	if _, err := decryptBytes(enc, "wrong"); err == nil {
		t.Fatal("expected fail with wrong key")
	}
}
