package vault

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dreamreflexsec/yukvault/internal/mount"
)

func TestHeaderRoundTrip(t *testing.T) {
	var header Header
	copy(header.Magic[:], []byte(Magic))
	header.Version = Version
	header.Flags = FlagRecovery
	copy(header.VaultID[:], []byte("0123456789abcdef0123456789abcdef"))
	copy(header.CredIDHash[:], []byte("fedcba9876543210fedcba9876543210"))
	copy(header.Nonce[:], []byte("nonce-123456"))
	header.PlaintextSize = 12345
	copy(header.GCMTag[:], []byte("tag-123456789012"))

	data, err := header.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	var decoded Header
	if err := decoded.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if !reflect.DeepEqual(header, decoded) {
		t.Fatalf("round-trip mismatch: %#v != %#v", header, decoded)
	}
}

func TestRecoveryTrailerRoundTrip(t *testing.T) {
	trailer := NewRecoveryTrailer()
	copy(trailer.Argon2Salt[:], []byte("0123456789abcdef"))
	trailer.Argon2Time = 3
	trailer.Argon2Memory = 64 * 1024
	trailer.Argon2Threads = 4
	copy(trailer.RecovKeyHash[:], []byte("0123456789abcdef0123456789abcdef"))
	copy(trailer.RecovNonce[:], []byte("nonce-123456"))
	copy(trailer.RecovTag[:], []byte("tag-123456789012"))
	copy(trailer.RecovCipher[:], []byte("0123456789abcdef0123456789abcdef"))

	data, err := trailer.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	var decoded RecoveryTrailer
	if err := decoded.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if !reflect.DeepEqual(trailer, decoded) {
		t.Fatalf("round-trip mismatch: %#v != %#v", trailer, decoded)
	}
}

func TestHeaderValidateRejectsCompressedFlag(t *testing.T) {
	header := NewHeader([32]byte{}, [32]byte{}, 0)
	header.Flags = FlagCompressed
	if err := header.Validate(); err == nil || !strings.Contains(err.Error(), "compressed vault payloads") {
		t.Fatalf("expected compressed flag to be rejected, got %v", err)
	}
}

func TestBuildAndValidateMountedEntry(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "yukvault-test-*.img")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if err := tmpFile.Chmod(0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := tmpFile.Write([]byte("test-image")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var vaultID [32]byte
	var credIDHash [32]byte
	copy(vaultID[:], []byte("0123456789abcdef0123456789abcdef"))
	copy(credIDHash[:], []byte("fedcba9876543210fedcba9876543210"))

	container := &Container{
		Path: filepath.Join(t.TempDir(), "vault.vault"),
		Header: Header{
			VaultID:       vaultID,
			CredIDHash:    credIDHash,
			PlaintextSize: 10,
		},
	}

	entry, err := BuildMountedEntry(
		container.Path,
		mount.MountInfo{ImagePath: tmpFile.Name(), MountPoint: filepath.Join(t.TempDir(), "mnt")},
		container,
	)
	if err != nil {
		t.Fatalf("BuildMountedEntry() error = %v", err)
	}
	if err := ValidateMountedEntry(entry, container); err != nil {
		t.Fatalf("ValidateMountedEntry() error = %v", err)
	}
}

func TestValidateMountedEntryRejectsMetadataMismatch(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "yukvault-test-*.img")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if err := tmpFile.Chmod(0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := tmpFile.Write([]byte("test-image")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var vaultID [32]byte
	var credIDHash [32]byte
	copy(vaultID[:], []byte("0123456789abcdef0123456789abcdef"))
	copy(credIDHash[:], []byte("fedcba9876543210fedcba9876543210"))

	container := &Container{
		Header: Header{
			VaultID:       vaultID,
			CredIDHash:    credIDHash,
			PlaintextSize: 10,
		},
	}

	entry := MountedEntry{
		VaultPath:      "vault.vault",
		ImagePath:      tmpFile.Name(),
		MountPoint:     "mnt",
		VaultID:        hex.EncodeToString(credIDHash[:]),
		CredIDHash:     hex.EncodeToString(credIDHash[:]),
		PlaintextSize:  10,
		ExpectedImgLen: 10,
	}
	if err := ValidateMountedEntry(entry, container); err == nil {
		t.Fatal("expected metadata mismatch to be rejected")
	}
}
