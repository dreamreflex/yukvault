//go:build linux

package mount

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func Mount(imagePath, target string) (*MountInfo, error) {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve mount target: %w", err)
	}
	if err := os.MkdirAll(absTarget, 0o755); err != nil {
		return nil, fmt.Errorf("create mount target: %w", err)
	}
	if _, err := exec.LookPath("fuse2fs"); err == nil {
		info, mountErr := mountFuse2fs(imagePath, absTarget)
		if mountErr == nil {
			return info, nil
		}
		if _, sudoErr := exec.LookPath("sudo"); sudoErr == nil {
			info, fallbackErr := mountSudo(imagePath, absTarget)
			if fallbackErr == nil {
				return info, nil
			}
			return nil, fmt.Errorf("fuse2fs mount failed: %v; sudo loop mount fallback failed: %w", mountErr, fallbackErr)
		}
		return nil, mountErr
	}
	return mountSudo(imagePath, absTarget)
}

func Unmount(info *MountInfo) error {
	absTarget, err := filepath.Abs(info.MountPoint)
	if err != nil {
		return fmt.Errorf("resolve mount point: %w", err)
	}
	info.MountPoint = absTarget
	mounted, err := isMounted(absTarget)
	if err != nil {
		return fmt.Errorf("check mount state before unmount: %w", err)
	}
	if !mounted {
		return nil
	}
	if _, err := exec.LookPath("fusermount"); err == nil {
		if output, cmdErr := exec.Command("fusermount", "-u", info.MountPoint).CombinedOutput(); cmdErr == nil {
			return ensureUnmounted(info.MountPoint)
		} else {
			return fmt.Errorf("fusermount -u: %w (%s)", cmdErr, string(output))
		}
	}
	if output, err := exec.Command("sudo", "umount", info.MountPoint).CombinedOutput(); err != nil {
		return fmt.Errorf("sudo umount: %w (%s)", err, string(output))
	}
	return ensureUnmounted(info.MountPoint)
}

func mountFuse2fs(imagePath, target string) (*MountInfo, error) {
	cmd := exec.Command("fuse2fs", imagePath, target, "-o", "rw,fakeroot")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start fuse2fs: %w", err)
	}
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mounted, err := isMounted(target)
		if err == nil && mounted {
			return &MountInfo{
				ImagePath:  imagePath,
				MountPoint: target,
				PID:        cmd.Process.Pid,
			}, nil
		}
		select {
		case err := <-waitCh:
			msg := strings.TrimSpace(out.String())
			if msg == "" {
				msg = "no output"
			}
			if err != nil {
				return nil, fmt.Errorf("fuse2fs exited before mount became active: %w (%s)", err, msg)
			}
			return nil, fmt.Errorf("fuse2fs exited without mounting target (%s)", msg)
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	msg := strings.TrimSpace(out.String())
	if msg == "" {
		msg = "no output"
	}
	return nil, fmt.Errorf("timed out waiting for fuse2fs mount at %s (%s)", target, msg)
}

func mountSudo(imagePath, target string) (*MountInfo, error) {
	output, err := exec.Command("sudo", "mount", "-o", "loop", imagePath, target).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sudo mount -o loop: %w (%s)", err, string(output))
	}
	if err := ensureMounted(target); err != nil {
		return nil, fmt.Errorf("verify loop mount: %w", err)
	}
	return &MountInfo{
		ImagePath:  imagePath,
		MountPoint: target,
		PID:        0,
	}, nil
}

func isMounted(target string) (bool, error) {
	cmd := exec.Command("mountpoint", "-q", target)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 32 {
			return false, nil
		}
		return false, fmt.Errorf("mountpoint -q %s: %w", target, err)
	}
	return true, nil
}

func ensureMounted(target string) error {
	mounted, err := isMounted(target)
	if err != nil {
		return err
	}
	if !mounted {
		return fmt.Errorf("target %s is not mounted", target)
	}
	return nil
}

func ensureUnmounted(target string) error {
	mounted, err := isMounted(target)
	if err != nil {
		return err
	}
	if mounted {
		return fmt.Errorf("target %s is still mounted", target)
	}
	return nil
}
