package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dreamreflexsec/yukvault/internal/mount"
	"github.com/dreamreflexsec/yukvault/internal/vault"
)

func mountAndRecord(vaultFilePath, imagePath, mountPoint string, container *vault.Container) error {
	absMountPoint := absPath(mountPoint)
	info, err := mount.Mount(imagePath, absMountPoint)
	if err != nil {
		_ = vault.Shred(imagePath)
		return fmt.Errorf("mount image: %w", err)
	}
	info.VaultPath = absPath(vaultFilePath)
	info.MountPoint = absMountPoint
	entry, err := vault.BuildMountedEntry(vaultFilePath, *info, container)
	if err != nil {
		_ = mount.Unmount(info)
		_ = vault.Shred(imagePath)
		return fmt.Errorf("build mount record: %w", err)
	}
	if err := vault.AddVerifiedMount(vault.DefaultStatePath(), entry); err != nil {
		_ = mount.Unmount(info)
		_ = vault.Shred(imagePath)
		return fmt.Errorf("record mount: %w", err)
	}
	return nil
}

func copyFile(srcPath, dstPath string, mode os.FileMode) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source file %q: %w", srcPath, err)
	}
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("open destination file %q: %w", dstPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copy %q to %q: %w", srcPath, dstPath, err)
	}
	if err := dst.Sync(); err != nil {
		return fmt.Errorf("sync destination file %q: %w", dstPath, err)
	}
	return nil
}

func backupFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat file %q: %w", path, err)
	}
	backupPath := path + ".bak"
	if err := copyFile(path, backupPath, info.Mode().Perm()); err != nil {
		return "", fmt.Errorf("create backup for %q: %w", path, err)
	}
	return backupPath, nil
}

func replaceFileFromTemp(tmpPath, finalPath string) error {
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename %q to %q: %w", filepath.Base(tmpPath), finalPath, err)
	}
	if err := syncDir(filepath.Dir(finalPath)); err != nil {
		return fmt.Errorf("sync directory for %q: %w", finalPath, err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := ensureDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file %q: %w", path, err)
	}
	tmpPath := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temp file %q: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp file %q: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp file %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file %q: %w", path, err)
	}
	return replaceFileFromTemp(tmpPath, path)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
