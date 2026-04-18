package vault

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	Magic          = "VLTX"
	TrailerMagic   = "RECV"
	HeaderSize     = 107
	TrailerSize    = 124
	Version        = 0x01
	FlagRecovery   = uint16(1 << 0)
	FlagCompressed = uint16(1 << 1)
)

type Header struct {
	Magic         [4]byte
	Version       uint8
	Flags         uint16
	VaultID       [32]byte
	CredIDHash    [32]byte
	Nonce         [12]byte
	PlaintextSize uint64
	GCMTag        [16]byte
}

func (h *Header) MarshalBinary() ([]byte, error) {
	buf := make([]byte, HeaderSize)
	copy(buf[0:4], h.Magic[:])
	buf[4] = h.Version
	binary.LittleEndian.PutUint16(buf[5:7], h.Flags)
	copy(buf[7:39], h.VaultID[:])
	copy(buf[39:71], h.CredIDHash[:])
	copy(buf[71:83], h.Nonce[:])
	binary.LittleEndian.PutUint64(buf[83:91], h.PlaintextSize)
	copy(buf[91:107], h.GCMTag[:])
	return buf, nil
}

func (h *Header) UnmarshalBinary(b []byte) error {
	if len(b) != HeaderSize {
		return fmt.Errorf("invalid header length: got %d want %d", len(b), HeaderSize)
	}
	copy(h.Magic[:], b[0:4])
	h.Version = b[4]
	h.Flags = binary.LittleEndian.Uint16(b[5:7])
	copy(h.VaultID[:], b[7:39])
	copy(h.CredIDHash[:], b[39:71])
	copy(h.Nonce[:], b[71:83])
	h.PlaintextSize = binary.LittleEndian.Uint64(b[83:91])
	copy(h.GCMTag[:], b[91:107])
	return nil
}

type RecoveryTrailer struct {
	Magic         [4]byte
	Argon2Salt    [16]byte
	Argon2Time    uint32
	Argon2Memory  uint32
	Argon2Threads uint32
	RecovKeyHash  [32]byte
	RecovNonce    [12]byte
	RecovTag      [16]byte
	RecovCipher   [32]byte
}

func (r *RecoveryTrailer) MarshalBinary() ([]byte, error) {
	buf := make([]byte, TrailerSize)
	copy(buf[0:4], r.Magic[:])
	copy(buf[4:20], r.Argon2Salt[:])
	binary.LittleEndian.PutUint32(buf[20:24], r.Argon2Time)
	binary.LittleEndian.PutUint32(buf[24:28], r.Argon2Memory)
	binary.LittleEndian.PutUint32(buf[28:32], r.Argon2Threads)
	copy(buf[32:64], r.RecovKeyHash[:])
	copy(buf[64:76], r.RecovNonce[:])
	copy(buf[76:92], r.RecovTag[:])
	copy(buf[92:124], r.RecovCipher[:])
	return buf, nil
}

func (r *RecoveryTrailer) UnmarshalBinary(b []byte) error {
	if len(b) != TrailerSize {
		return fmt.Errorf("invalid trailer length: got %d want %d", len(b), TrailerSize)
	}
	copy(r.Magic[:], b[0:4])
	copy(r.Argon2Salt[:], b[4:20])
	r.Argon2Time = binary.LittleEndian.Uint32(b[20:24])
	r.Argon2Memory = binary.LittleEndian.Uint32(b[24:28])
	r.Argon2Threads = binary.LittleEndian.Uint32(b[28:32])
	copy(r.RecovKeyHash[:], b[32:64])
	copy(r.RecovNonce[:], b[64:76])
	copy(r.RecovTag[:], b[76:92])
	copy(r.RecovCipher[:], b[92:124])
	return nil
}

func AAD(h *Header) []byte {
	buf := make([]byte, 71)
	copy(buf[0:4], h.Magic[:])
	buf[4] = h.Version
	binary.LittleEndian.PutUint16(buf[5:7], h.Flags)
	copy(buf[7:39], h.VaultID[:])
	copy(buf[39:71], h.CredIDHash[:])
	return buf
}

func NewHeader(vaultID, credIDHash [32]byte, plaintextSize uint64) Header {
	var magic [4]byte
	copy(magic[:], []byte(Magic))
	return Header{
		Magic:         magic,
		Version:       Version,
		VaultID:       vaultID,
		CredIDHash:    credIDHash,
		PlaintextSize: plaintextSize,
	}
}

func NewRecoveryTrailer() RecoveryTrailer {
	var magic [4]byte
	copy(magic[:], []byte(TrailerMagic))
	return RecoveryTrailer{Magic: magic}
}

func (h Header) Validate() error {
	if !bytes.Equal(h.Magic[:], []byte(Magic)) {
		return fmt.Errorf("invalid header magic")
	}
	if h.Version != Version {
		return fmt.Errorf("unsupported version: %d", h.Version)
	}
	if h.Flags&^(FlagRecovery|FlagCompressed) != 0 {
		return fmt.Errorf("unsupported header flags: 0x%x", h.Flags)
	}
	if h.Flags&FlagCompressed != 0 {
		return fmt.Errorf("compressed vault payloads are not supported")
	}
	return nil
}

func (r RecoveryTrailer) Validate() error {
	if !bytes.Equal(r.Magic[:], []byte(TrailerMagic)) {
		return fmt.Errorf("invalid recovery trailer magic")
	}
	if r.Argon2Time == 0 || r.Argon2Memory == 0 || r.Argon2Threads == 0 {
		return fmt.Errorf("invalid recovery trailer Argon2 parameters")
	}
	return nil
}
