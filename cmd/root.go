package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	vaultPath  string
	devicePath string
)

var rootCmd = &cobra.Command{
	Use:   "yukvault",
	Short: "Hardware-backed encrypted file vault using YubiKey FIDO2",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&vaultPath, "vault", "./vault.vault", "path to .vault file")
	rootCmd.PersistentFlags().StringVar(&devicePath, "device", "", "FIDO2 device path")
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(openCmd)
	rootCmd.AddCommand(closeCmd)
	rootCmd.AddCommand(recoverCmd)
	rootCmd.AddCommand(rotateCmd)
	rootCmd.AddCommand(listCmd)
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	defer fmt.Fprintln(os.Stderr)

	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(raw), nil
}

func credIDSidecarPath(vault string) string {
	return vault + ".credid"
}

func ensureDir(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create directory %q: %w", path, err)
	}
	return nil
}

func absPath(path string) string {
	if path == "" {
		return path
	}
	out, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return out
}
