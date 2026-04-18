package mount

type MountInfo struct {
	VaultPath  string
	ImagePath  string
	MountPoint string
	PID        int
}
