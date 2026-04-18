package crypto

import "testing"

func TestSealOpen_RoundTrip(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	plaintext := []byte("hello vault")
	aad := []byte("aad")

	nonce, ciphertext, tag, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	got, err := Open(key, nonce, ciphertext, tag, aad)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}

func TestOpen_WrongKey(t *testing.T) {
	var key [32]byte
	var wrong [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	copy(wrong[:], []byte("fedcba9876543210fedcba9876543210"))

	nonce, ciphertext, tag, err := Seal(key, []byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if _, err := Open(wrong, nonce, ciphertext, tag, []byte("aad")); err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestOpen_TamperedCiphertext(t *testing.T) {
	var key [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))

	nonce, ciphertext, tag, err := Seal(key, []byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	ciphertext[0] ^= 0xff
	if _, err := Open(key, nonce, ciphertext, tag, []byte("aad")); err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}
