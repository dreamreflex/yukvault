package crypto

import "testing"

func TestDeriveVaultKey_Deterministic(t *testing.T) {
	hmacOutput := []byte("0123456789abcdef0123456789abcdef")
	vaultID := []byte("vault-id-0123456789abcdef01234567")

	first, err := DeriveVaultKey(hmacOutput, vaultID)
	if err != nil {
		t.Fatalf("DeriveVaultKey() error = %v", err)
	}
	second, err := DeriveVaultKey(hmacOutput, vaultID)
	if err != nil {
		t.Fatalf("DeriveVaultKey() error = %v", err)
	}
	if first != second {
		t.Fatalf("expected deterministic keys, got %x and %x", first, second)
	}
}

func TestDeriveVaultKey_DifferentVaultID(t *testing.T) {
	hmacOutput := []byte("0123456789abcdef0123456789abcdef")
	firstVaultID := []byte("vault-id-0123456789abcdef01234567")
	secondVaultID := []byte("vault-id-76543210fedcba9876543210")

	first, err := DeriveVaultKey(hmacOutput, firstVaultID)
	if err != nil {
		t.Fatalf("DeriveVaultKey() error = %v", err)
	}
	second, err := DeriveVaultKey(hmacOutput, secondVaultID)
	if err != nil {
		t.Fatalf("DeriveVaultKey() error = %v", err)
	}
	if first == second {
		t.Fatalf("expected different keys for different vault ids")
	}
}
