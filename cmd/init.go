package cmd

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dreamreflexsec/yukvault/internal/crypto"
	"github.com/dreamreflexsec/yukvault/internal/vault"
	"github.com/dreamreflexsec/yukvault/internal/yubikey"
	"github.com/spf13/cobra"
)

var (
	initSize    string
	initMount   string
	initRecover bool
	initFS      string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		if vaultPath == "" {
			return fmt.Errorf("vault path is required")
		}
		if _, err := os.Stat(vaultPath); err == nil {
			return fmt.Errorf("vault already exists: %s", vaultPath)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat vault path: %w", err)
		}

		sizeBytes, err := vault.ParseSize(initSize)
		if err != nil {
			return fmt.Errorf("parse size: %w", err)
		}

		if err := ensureDir(filepath.Dir(vaultPath)); err != nil {
			return err
		}

		dev, err := yubikey.SelectDevice(devicePath)
		if err != nil {
			return fmt.Errorf("select device: %w", err)
		}

		pin, err := readPassword("Enter YubiKey PIN: ")
		if err != nil {
			return err
		}
		confirm, err := readPassword("Confirm YubiKey PIN: ")
		if err != nil {
			return err
		}
		if pin != confirm {
			return fmt.Errorf("PINs do not match")
		}

		var vaultID [32]byte
		if _, err := rand.Read(vaultID[:]); err != nil {
			return fmt.Errorf("generate vault id: %w", err)
		}

		credentialID, err := yubikey.MakeCredential(dev.Path, pin, vault.ClientDataHashInit(vaultID), vaultID)
		if err != nil {
			return fmt.Errorf("make credential: %w", err)
		}
		credSidecarPath := credIDSidecarPath(vaultPath)
		if err := writeFileAtomic(credSidecarPath, credentialID, 0o600); err != nil {
			return fmt.Errorf("write credential sidecar: %w", err)
		}
		sidecarCreated := true
		defer func() {
			if sidecarCreated {
				_ = vault.Shred(credSidecarPath)
			}
		}()

		hmacOutput, err := yubikey.GetHMACSecret(dev.Path, pin, credentialID, vault.ClientDataHashOpen(vaultID), vaultID[:])
		if err != nil {
			return fmt.Errorf("get hmac secret: %w", err)
		}
		defer crypto.Memzero(hmacOutput)

		keyBytes, err := crypto.NewLockedBuffer(32)
		if err != nil {
			return fmt.Errorf("allocate vault key: %w", err)
		}
		defer crypto.ReleaseLockedBuffer(keyBytes)

		derivedKey, err := crypto.DeriveVaultKey(hmacOutput, vaultID[:])
		if err != nil {
			return fmt.Errorf("derive vault key: %w", err)
		}
		copy(keyBytes, derivedKey[:])

		mnemonic, err := vault.Initialize(vault.InitializeOptions{
			VaultPath: vaultPath,
			VaultID:   vaultID,
			CredID:    credentialID,
			VaultKey:  keyBytes,
			SizeBytes: sizeBytes,
			FS:        initFS,
			Recover:   initRecover,
		})
		if err != nil {
			return fmt.Errorf("initialize vault: %w", err)
		}
		sidecarCreated = false

		if initMount != "" {
			if err := ensureDir(initMount); err != nil {
				return err
			}
			container, err := vault.LoadContainer(vaultPath)
			if err != nil {
				return fmt.Errorf("reload vault after init: %w", err)
			}
			imagePath, err := container.WriteTempImage(keyBytes)
			if err != nil {
				return fmt.Errorf("create temp image for mount: %w", err)
			}
			if err := mountAndRecord(vaultPath, imagePath, initMount, container); err != nil {
				return err
			}
		}

		if mnemonic != "" {
			fmt.Print(vault.FormatRecoveryMnemonic(mnemonic))
			fmt.Fprintf(os.Stderr, "Vault created: %s\n", absPath(vaultPath))
			return nil
		}
		fmt.Printf("Vault created: %s\n", absPath(vaultPath))
		return nil
	},
}

func init() {
	initCmd.Flags().StringVar(&initSize, "size", "256M", "vault size")
	initCmd.Flags().StringVar(&initMount, "mount", "", "directory to mount after creation")
	initCmd.Flags().BoolVar(&initRecover, "recover", false, "generate a recovery key")
	initCmd.Flags().StringVar(&initFS, "fs", "ext4", "filesystem type: ext4|exfat")
	_ = initCmd.MarkFlagRequired("vault")
}
