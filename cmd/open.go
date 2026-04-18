package cmd

import (
	"fmt"

	"github.com/dreamreflexsec/yukvault/internal/crypto"
	"github.com/dreamreflexsec/yukvault/internal/vault"
	"github.com/dreamreflexsec/yukvault/internal/yubikey"
	"github.com/spf13/cobra"
)

var openMount string

var openCmd = &cobra.Command{
	Use:   "open",
	Short: "Open and mount a vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		if openMount == "" {
			return fmt.Errorf("mount target is required")
		}

		container, err := vault.LoadContainer(vaultPath)
		if err != nil {
			return fmt.Errorf("load vault: %w", err)
		}

		credentialID, err := vault.ReadCredentialID(credIDSidecarPath(vaultPath))
		if err != nil {
			return fmt.Errorf("read credential sidecar: %w", err)
		}
		if err := container.VerifyCredentialID(credentialID); err != nil {
			return fmt.Errorf("verify credential id: %w", err)
		}

		dev, err := yubikey.SelectDevice(devicePath)
		if err != nil {
			return fmt.Errorf("select device: %w", err)
		}
		pin, err := readPassword("Enter YubiKey PIN: ")
		if err != nil {
			return err
		}

		hmacOutput, err := yubikey.GetHMACSecret(dev.Path, pin, credentialID, vault.ClientDataHashOpen(container.Header.VaultID), container.Header.VaultID[:])
		if err != nil {
			return fmt.Errorf("get hmac secret: %w", err)
		}
		defer crypto.Memzero(hmacOutput)

		keyBytes, err := crypto.NewLockedBuffer(32)
		if err != nil {
			return fmt.Errorf("allocate vault key: %w", err)
		}
		defer crypto.ReleaseLockedBuffer(keyBytes)

		derivedKey, err := crypto.DeriveVaultKey(hmacOutput, container.Header.VaultID[:])
		if err != nil {
			return fmt.Errorf("derive vault key: %w", err)
		}
		copy(keyBytes, derivedKey[:])

		imagePath, err := container.WriteTempImage(keyBytes)
		if err != nil {
			return fmt.Errorf("write temp image: %w", err)
		}

		if err := mountAndRecord(vaultPath, imagePath, openMount, container); err != nil {
			return err
		}

		fmt.Printf("Vault mounted at %s\n", openMount)
		return nil
	},
}

func init() {
	openCmd.Flags().StringVar(&openMount, "mount", "", "mount target")
	_ = openCmd.MarkFlagRequired("vault")
}
