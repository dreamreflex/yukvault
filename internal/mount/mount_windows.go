//go:build windows

package mount

import (
	"fmt"
	"os/exec"
)

func Mount(imagePath, target string) (*MountInfo, error) {
	output, err := exec.Command("imdisk", "-a", "-f", imagePath, "-m", target).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("imdisk mount: %w (%s)", err, string(output))
	}
	return &MountInfo{
		ImagePath:  imagePath,
		MountPoint: target,
		PID:        0,
	}, nil
}

func Unmount(info *MountInfo) error {
	output, err := exec.Command("imdisk", "-d", "-m", info.MountPoint).CombinedOutput()
	if err != nil {
		return fmt.Errorf("imdisk unmount: %w (%s)", err, string(output))
	}
	return nil
}
