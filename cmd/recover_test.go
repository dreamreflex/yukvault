package cmd

import "testing"

func TestNormalizeRecoveryKeyRejects12WordMnemonic(t *testing.T) {
	_, err := normalizeRecoveryKey("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err == nil {
		t.Fatal("expected 12-word mnemonic to be rejected")
	}
}

func TestNormalizeRecoveryKeyRejectsShortHex(t *testing.T) {
	_, err := normalizeRecoveryKey("deadbeef")
	if err == nil {
		t.Fatal("expected short hex recovery key to be rejected")
	}
}
