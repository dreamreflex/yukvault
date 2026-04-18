package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	ArgonTime    uint32 = 3
	ArgonMemory  uint32 = 64 * 1024
	ArgonThreads uint8  = 4
	ArgonKeyLen         = 32
)

func DeriveVaultKey(hmacOutput, vaultID []byte) ([32]byte, error) {
	r := hkdf.New(sha256.New, hmacOutput, vaultID, []byte("vault-key-v1"))
	var key [32]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

func StretchRecoveryKey(passphrase string, salt [16]byte) [32]byte {
	raw := argon2.IDKey([]byte(passphrase), salt[:], ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
	var out [32]byte
	copy(out[:], raw)
	return out
}

func HashRecoveryKey(stretchedKey []byte, salt [16]byte, time uint32, memory uint32, threads uint32) [32]byte {
	raw := argon2.IDKey(stretchedKey, salt[:], time, memory, uint8(threads), 32)
	var out [32]byte
	copy(out[:], raw)
	return out
}
