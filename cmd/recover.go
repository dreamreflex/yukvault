package cmd

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/dreamreflexsec/yukvault/internal/bip39"
	"github.com/dreamreflexsec/yukvault/internal/crypto"
	"github.com/dreamreflexsec/yukvault/internal/vault"
	"github.com/spf13/cobra"
)

var (
	recoverKey   string
	recoverMount string
)

var recoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover a vault using the recovery key",
	RunE: func(cmd *cobra.Command, args []string) error {
		if recoverMount == "" {
			return fmt.Errorf("mount target is required")
		}

		container, err := vault.LoadContainer(vaultPath)
		if err != nil {
			return fmt.Errorf("load vault: %w", err)
		}
		if container.Trailer == nil || container.Header.Flags&vault.FlagRecovery == 0 {
			return fmt.Errorf("vault does not contain a recovery key")
		}

		recoveryInput, err := readRecoveryKey(recoverKey)
		if err != nil {
			return err
		}

		passphrase, err := normalizeRecoveryKey(recoveryInput)
		if err != nil {
			return fmt.Errorf("parse recovery key: %w", err)
		}

		stretched := crypto.StretchRecoveryKey(passphrase, container.Trailer.Argon2Salt)
		if err := container.VerifyRecoveryKey(stretched); err != nil {
			return fmt.Errorf("verify recovery key: %w", err)
		}
		keyBytes, err := crypto.NewLockedBuffer(32)
		if err != nil {
			return fmt.Errorf("allocate vault key: %w", err)
		}
		defer crypto.ReleaseLockedBuffer(keyBytes)

		if err := container.RecoverVaultKeyInto(stretched, keyBytes); err != nil {
			return fmt.Errorf("recover vault key: %w", err)
		}

		imagePath, err := container.WriteTempImage(keyBytes)
		if err != nil {
			return fmt.Errorf("write temp image: %w", err)
		}
		if err := mountAndRecord(vaultPath, imagePath, recoverMount, container); err != nil {
			return err
		}
		fmt.Printf("Vault mounted at %s\n", recoverMount)
		return nil
	},
}

func init() {
	recoverCmd.Flags().StringVar(&recoverKey, "key", "", "BIP-39 mnemonic phrase or hex string; if omitted, read securely from the terminal")
	recoverCmd.Flags().StringVar(&recoverMount, "mount", "", "mount target")
	_ = recoverCmd.MarkFlagRequired("vault")
}

func readRecoveryKey(flagValue string) (string, error) {
	if strings.TrimSpace(flagValue) != "" {
		return flagValue, nil
	}
	value, err := readPassword("Enter recovery key: ")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("recovery key is required")
	}
	return value, nil
}

func normalizeRecoveryKey(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	words := strings.Fields(trimmed)
	if len(words) > 0 {
		if len(words) != 24 {
			return "", fmt.Errorf("recovery mnemonic must contain exactly 24 words")
		}
		if !bip39.IsMnemonicValid(trimmed) {
			return "", fmt.Errorf("invalid BIP-39 mnemonic")
		}
		entropy, err := bip39.EntropyFromMnemonic(trimmed)
		if err != nil {
			return "", fmt.Errorf("decode mnemonic: %w", err)
		}
		return hex.EncodeToString(entropy), nil
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return "", fmt.Errorf("decode hex recovery key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("recovery key hex must decode to exactly 32 bytes")
	}
	return hex.EncodeToString(raw), nil
}
