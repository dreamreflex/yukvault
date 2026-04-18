//go:build windows

package crypto

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
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
	return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func Munlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
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
