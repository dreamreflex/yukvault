package cmd

import (
	"fmt"
	"os"

	"github.com/dreamreflexsec/yukvault/internal/crypto"
	"github.com/dreamreflexsec/yukvault/internal/mount"
	"github.com/dreamreflexsec/yukvault/internal/vault"
	"github.com/dreamreflexsec/yukvault/internal/yubikey"
	"github.com/spf13/cobra"
)

var closeMount string

var closeCmd = &cobra.Command{
	Use:   "close",
	Short: "Close a mounted vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		statePath := vault.DefaultStatePath()
		entry, err := vault.FindMount(statePath, vaultPath, closeMount)
		if err != nil {
			return fmt.Errorf("find mounted vault: %w", err)
		}
		info := &mount.MountInfo{
			VaultPath:  entry.VaultPath,
			ImagePath:  entry.ImagePath,
			MountPoint: entry.MountPoint,
		}
		keyBytes, err := prepareClose(entry, devicePath)
		if err != nil {
			return fmt.Errorf("close mounted vault: %w", err)
		}
		defer crypto.ReleaseLockedBuffer(keyBytes)
		if err := mount.Unmount(info); err != nil {
			return fmt.Errorf("unmount image: %w", err)
		}
		if err := closeAndSaveVault(entry, keyBytes); err != nil {
			return fmt.Errorf("close mounted vault: %w", err)
		}
		if err := vault.RemoveMount(statePath, entry); err != nil {
			return fmt.Errorf("update mount state: %w", err)
		}
		fmt.Println("Vault closed and saved")
		return nil
	},
}

func init() {
	closeCmd.Flags().StringVar(&closeMount, "mount", "", "mount point to identify which vault to close")
}

func prepareClose(entry vault.MountedEntry, preferredDevice string) ([]byte, error) {
	container, err := vault.LoadContainer(entry.VaultPath)
	if err != nil {
		return nil, fmt.Errorf("load container: %w", err)
	}
	if err := vault.ValidateMountedEntry(entry, container); err != nil {
		return nil, fmt.Errorf("validate mounted entry: %w", err)
	}
	credentialID, err := vault.ReadCredentialID(credIDSidecarPath(entry.VaultPath))
	if err != nil {
		return nil, fmt.Errorf("read credential id: %w", err)
	}
	if err := container.VerifyCredentialID(credentialID); err != nil {
		return nil, fmt.Errorf("verify credential id: %w", err)
	}

	dev, err := yubikey.SelectDevice(preferredDevice)
	if err != nil {
		return nil, fmt.Errorf("select device: %w", err)
	}
	pin, err := readPassword("Enter YubiKey PIN: ")
	if err != nil {
		return nil, err
	}

	hmacOutput, err := yubikey.GetHMACSecret(dev.Path, pin, credentialID, vault.ClientDataHashOpen(container.Header.VaultID), container.Header.VaultID[:])
	if err != nil {
		return nil, fmt.Errorf("get hmac secret: %w", err)
	}
	defer crypto.Memzero(hmacOutput)

	keyBytes, err := crypto.NewLockedBuffer(32)
	if err != nil {
		return nil, fmt.Errorf("allocate vault key: %w", err)
	}
	derivedKey, err := crypto.DeriveVaultKey(hmacOutput, container.Header.VaultID[:])
	if err != nil {
		crypto.ReleaseLockedBuffer(keyBytes)
		return nil, fmt.Errorf("derive vault key: %w", err)
	}
	copy(keyBytes, derivedKey[:])
	return keyBytes, nil
}

func closeAndSaveVault(entry vault.MountedEntry, keyBytes []byte) error {
	container, err := vault.LoadContainer(entry.VaultPath)
	if err != nil {
		return fmt.Errorf("load container: %w", err)
	}
	if err := vault.ValidateMountedEntry(entry, container); err != nil {
		return fmt.Errorf("validate mounted entry after unmount: %w", err)
	}
	plaintext, err := os.ReadFile(entry.ImagePath)
	if err != nil {
		return fmt.Errorf("read temp image: %w", err)
	}
	defer crypto.Memzero(plaintext)
	if err := container.EncryptWithVaultKey(keyBytes, plaintext); err != nil {
		return fmt.Errorf("encrypt updated image: %w", err)
	}
	if err := container.WriteAtomic(); err != nil {
		return fmt.Errorf("write updated vault: %w", err)
	}
	if err := vault.Shred(entry.ImagePath); err != nil {
		return fmt.Errorf("remove temp image after successful save: %w", err)
	}
	return nil
}
