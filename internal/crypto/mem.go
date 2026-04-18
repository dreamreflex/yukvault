//go:build linux

package crypto

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func Memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func Mlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

func Munlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}

func NewLockedBuffer(size int) ([]byte, error) {
	buf := make([]byte, size)
	if err := Mlock(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func ReleaseLockedBuffer(buf []byte) {
	Memzero(buf)
	_ = Munlock(buf)
}
