//go:build !linux && !windows

package mount

import "fmt"

func Mount(imagePath, target string) (*MountInfo, error) {
	return nil, fmt.Errorf("unsupported platform: yukvault currently supports only Linux and Windows")
}

func Unmount(info *MountInfo) error {
	return fmt.Errorf("unsupported platform: yukvault currently supports only Linux and Windows")
}
