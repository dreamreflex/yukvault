package cmd

import (
	"fmt"
	"time"

	"github.com/dreamreflexsec/yukvault/internal/vault"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List mounted vaults",
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := vault.LoadState(vault.DefaultStatePath())
		if err != nil {
			return fmt.Errorf("load mount state: %w", err)
		}
		fmt.Println("VAULT PATH\tMOUNT POINT\tOPENED AT")
		for _, entry := range state.Mounts {
			opened := entry.OpenedAt.Format(time.DateTime)
			fmt.Printf("%s\t%s\t%s\n", entry.VaultPath, entry.MountPoint, opened)
		}
		return nil
	},
}
