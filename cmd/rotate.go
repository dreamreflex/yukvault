package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/dreamreflexsec/yukvault/internal/crypto"
	"github.com/dreamreflexsec/yukvault/internal/vault"
	"github.com/dreamreflexsec/yukvault/internal/yubikey"
	"github.com/spf13/cobra"
)

var rotateMount string

var rotateCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Rotate the YubiKey credential and vault key",
	RunE: func(cmd *cobra.Command, args []string) error {
		if rotateMount != "" {
			return fmt.Errorf("rotate-key does not accept a mounted vault")
		}
		state, err := vault.LoadState(vault.DefaultStatePath())
		if err != nil {
			return fmt.Errorf("load mount state: %w", err)
		}
		for _, entry := range state.Mounts {
			if entry.VaultPath == absPath(vaultPath) {
				return fmt.Errorf("vault is currently mounted at %s", entry.MountPoint)
			}
		}
		return rotateVaultKey(vaultPath, devicePath)
	},
}

func init() {
	rotateCmd.Flags().StringVar(&rotateMount, "mount", "", "must not be currently mounted")
	_ = rotateCmd.MarkFlagRequired("vault")
}

func rotateVaultKey(vaultPath, preferredDevice string) error {
	container, err := vault.LoadContainer(vaultPath)
	if err != nil {
		return fmt.Errorf("load container: %w", err)
	}
	credentialID, err := vault.ReadCredentialID(credIDSidecarPath(vaultPath))
	if err != nil {
		return fmt.Errorf("read credential id: %w", err)
	}
	if err := container.VerifyCredentialID(credentialID); err != nil {
		return fmt.Errorf("verify credential id: %w", err)
	}

	dev, err := yubikey.SelectDevice(preferredDevice)
	if err != nil {
		return fmt.Errorf("select device: %w", err)
	}
	pin, err := readPassword("Enter YubiKey PIN: ")
	if err != nil {
		return err
	}

	oldHMAC, err := yubikey.GetHMACSecret(dev.Path, pin, credentialID, vault.ClientDataHashOpen(container.Header.VaultID), container.Header.VaultID[:])
	if err != nil {
		return fmt.Errorf("get existing hmac secret: %w", err)
	}
	defer crypto.Memzero(oldHMAC)

	oldKey, err := crypto.NewLockedBuffer(32)
	if err != nil {
		return fmt.Errorf("allocate existing vault key: %w", err)
	}
	defer crypto.ReleaseLockedBuffer(oldKey)

	derivedOldKey, err := crypto.DeriveVaultKey(oldHMAC, container.Header.VaultID[:])
	if err != nil {
		return fmt.Errorf("derive existing vault key: %w", err)
	}
	copy(oldKey, derivedOldKey[:])

	plaintext, err := container.Decrypt(oldKey)
	if err != nil {
		return fmt.Errorf("decrypt existing payload: %w", err)
	}
	defer crypto.Memzero(plaintext)

	hadRecovery := container.Header.Flags&vault.FlagRecovery != 0

	var newVaultID [32]byte
	if _, err := rand.Read(newVaultID[:]); err != nil {
		return fmt.Errorf("generate new vault id: %w", err)
	}
	newCredentialID, err := yubikey.MakeCredential(dev.Path, pin, vault.ClientDataHashInit(newVaultID), newVaultID)
	if err != nil {
		return fmt.Errorf("make new credential: %w", err)
	}
	newHMAC, err := yubikey.GetHMACSecret(dev.Path, pin, newCredentialID, vault.ClientDataHashOpen(newVaultID), newVaultID[:])
	if err != nil {
		return fmt.Errorf("get new hmac secret: %w", err)
	}
	defer crypto.Memzero(newHMAC)

	newKey, err := crypto.NewLockedBuffer(32)
	if err != nil {
		return fmt.Errorf("allocate new vault key: %w", err)
	}
	defer crypto.ReleaseLockedBuffer(newKey)

	derivedNewKey, err := crypto.DeriveVaultKey(newHMAC, newVaultID[:])
	if err != nil {
		return fmt.Errorf("derive new vault key: %w", err)
	}
	copy(newKey, derivedNewKey[:])

	container.Header.VaultID = newVaultID
	container.Header.CredIDHash = sha256.Sum256(newCredentialID)
	container.Header.Flags &^= vault.FlagRecovery
	container.Trailer = nil
	if err := container.EncryptWithVaultKey(newKey, plaintext); err != nil {
		return fmt.Errorf("re-encrypt payload: %w", err)
	}

	var mnemonic string
	if hadRecovery {
		mnemonic, _, err = container.AttachRecoveryKey(newKey)
		if err != nil {
			return fmt.Errorf("attach rotated recovery key: %w", err)
		}
	}

	vaultBackup, err := backupFile(vaultPath)
	if err != nil {
		return fmt.Errorf("backup vault file: %w", err)
	}
	credBackup, err := backupFile(credIDSidecarPath(vaultPath))
	if err != nil {
		_ = vault.Shred(vaultBackup)
		return fmt.Errorf("backup credential sidecar: %w", err)
	}
	defer func() {
		_ = vault.Shred(vaultBackup)
		_ = vault.Shred(credBackup)
	}()

	tmpCredPath := credIDSidecarPath(vaultPath) + ".tmp"
	if err := writeFileAtomic(tmpCredPath, newCredentialID, 0o600); err != nil {
		return fmt.Errorf("write new credential sidecar: %w", err)
	}
	if err := container.WriteAtomic(); err != nil {
		_ = os.Remove(tmpCredPath)
		return fmt.Errorf("write rotated vault: %w", err)
	}
	if err := replaceFileFromTemp(tmpCredPath, credIDSidecarPath(vaultPath)); err != nil {
		if restoreErr := copyFile(vaultBackup, vaultPath, 0o600); restoreErr != nil {
			return fmt.Errorf("replace credential sidecar: %w; rollback vault: %v", err, restoreErr)
		}
		return fmt.Errorf("replace credential sidecar: %w", err)
	}
	if mnemonic != "" {
		fmt.Print(vault.FormatRecoveryMnemonic(mnemonic))
		fmt.Fprintln(os.Stderr, "Vault key rotated successfully")
		return nil
	}
	fmt.Println("Vault key rotated successfully")
	return nil
}
