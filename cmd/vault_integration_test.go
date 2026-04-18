//go:build integration

package cmd

import "testing"

func TestFullVaultLifecycle(t *testing.T) {
	t.Skip("requires a real YubiKey, libfido2, and mount tooling")
}

func TestRecoveryKeyLifecycle(t *testing.T) {
	t.Skip("requires a real YubiKey, libfido2, and mount tooling")
}
