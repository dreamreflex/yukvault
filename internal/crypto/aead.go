package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func Seal(key [32]byte, plaintext, aad []byte) (nonce [12]byte, ciphertext []byte, tag [16]byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return
	}
	sealed := gcm.Seal(nil, nonce[:], plaintext, aad)
	ciphertext = sealed[:len(sealed)-16]
	copy(tag[:], sealed[len(sealed)-16:])
	return
}

func Open(key [32]byte, nonce [12]byte, ciphertext []byte, tag [16]byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	combined := make([]byte, 0, len(ciphertext)+len(tag))
	combined = append(combined, ciphertext...)
	combined = append(combined, tag[:]...)
	return gcm.Open(nil, nonce[:], combined, aad)
}
