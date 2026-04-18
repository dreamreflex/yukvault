package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreamreflexsec/yukvault/internal/bip39"
	crypto2 "github.com/dreamreflexsec/yukvault/internal/crypto"
	"github.com/dreamreflexsec/yukvault/internal/mount"
	"github.com/google/uuid"
)

const recoveryAAD = "recovery-key-v1"

type Container struct {
	Path       string
	Header     Header
	Ciphertext []byte
	Trailer    *RecoveryTrailer
}

type InitializeOptions struct {
	VaultPath string
	VaultID   [32]byte
	CredID    []byte
	VaultKey  []byte
	SizeBytes int64
	FS        string
	Recover   bool
}

type MountedEntry struct {
	VaultPath      string    `json:"vault_path"`
	ImagePath      string    `json:"image_path"`
	MountPoint     string    `json:"mount_point"`
	OpenedAt       time.Time `json:"opened_at"`
	VaultID        string    `json:"vault_id,omitempty"`
	CredIDHash     string    `json:"credid_hash,omitempty"`
	PlaintextSize  uint64    `json:"plaintext_size,omitempty"`
	ExpectedImgLen int64     `json:"expected_image_len,omitempty"`
}

type State struct {
	Mounts []MountedEntry `json:"mounts"`
}

func ParseSize(input string) (int64, error) {
	s := strings.TrimSpace(strings.ToUpper(input))
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, "K"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "G")
	}
	var size int64
	if _, err := fmt.Sscan(s, &size); err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", input, err)
	}
	if size <= 0 {
		return 0, fmt.Errorf("size must be positive")
	}
	return size * multiplier, nil
}

func ClientDataHashInit(vaultID [32]byte) []byte {
	sum := sha256.Sum256([]byte("yukvault-init-" + hex.EncodeToString(vaultID[:])))
	return sum[:]
}

func ClientDataHashOpen(vaultID [32]byte) []byte {
	sum := sha256.Sum256([]byte("yukvault-open-" + hex.EncodeToString(vaultID[:])))
	return sum[:]
}

func ReadCredentialID(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credential id: %w", err)
	}
	return data, nil
}

func Initialize(opts InitializeOptions) (string, error) {
	if len(opts.VaultKey) != 32 {
		return "", fmt.Errorf("vault key must be 32 bytes")
	}
	plainImage, imagePath, err := createFilesystemImage(opts.SizeBytes, opts.FS)
	if err != nil {
		return "", fmt.Errorf("create filesystem image: %w", err)
	}
	defer func() {
		crypto2.Memzero(plainImage)
		_ = shredFile(imagePath)
	}()

	credHash := sha256.Sum256(opts.CredID)
	var key [32]byte
	copy(key[:], opts.VaultKey)

	header := NewHeader(opts.VaultID, credHash, uint64(len(plainImage)))
	nonce, ciphertext, tag, err := crypto2.Seal(key, plainImage, AAD(&header))
	if err != nil {
		return "", fmt.Errorf("encrypt vault image: %w", err)
	}
	header.Nonce = nonce
	header.GCMTag = tag

	container := Container{
		Path:       opts.VaultPath,
		Header:     header,
		Ciphertext: ciphertext,
	}

	var mnemonic string
	if opts.Recover {
		mnemonic, _, err = container.AttachRecoveryKey(opts.VaultKey)
		if err != nil {
			return "", fmt.Errorf("attach recovery key: %w", err)
		}
	}

	if err := container.WriteAtomic(); err != nil {
		return "", fmt.Errorf("write vault container: %w", err)
	}

	return mnemonic, nil
}

func (c *Container) VerifyCredentialID(credentialID []byte) error {
	sum := sha256.Sum256(credentialID)
	if !bytes.Equal(sum[:], c.Header.CredIDHash[:]) {
		return fmt.Errorf("credential id hash mismatch")
	}
	return nil
}

func LoadContainer(path string) (*Container, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vault file: %w", err)
	}
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("vault file too small")
	}
	var header Header
	if err := header.UnmarshalBinary(data[:HeaderSize]); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if err := header.Validate(); err != nil {
		return nil, fmt.Errorf("validate header: %w", err)
	}

	end := len(data)
	var trailer *RecoveryTrailer
	if header.Flags&FlagRecovery != 0 {
		if len(data) < HeaderSize+TrailerSize {
			return nil, fmt.Errorf("vault file missing recovery trailer")
		}
		var rec RecoveryTrailer
		if err := rec.UnmarshalBinary(data[len(data)-TrailerSize:]); err != nil {
			return nil, fmt.Errorf("parse recovery trailer: %w", err)
		}
		if err := rec.Validate(); err != nil {
			return nil, fmt.Errorf("validate recovery trailer: %w", err)
		}
		trailer = &rec
		end -= TrailerSize
	}

	return &Container{
		Path:       path,
		Header:     header,
		Ciphertext: append([]byte(nil), data[HeaderSize:end]...),
		Trailer:    trailer,
	}, nil
}

func (c *Container) Decrypt(vaultKey []byte) ([]byte, error) {
	if len(vaultKey) != 32 {
		return nil, fmt.Errorf("vault key must be 32 bytes")
	}
	var key [32]byte
	copy(key[:], vaultKey)
	plaintext, err := crypto2.Open(key, c.Header.Nonce, c.Ciphertext, c.Header.GCMTag, AAD(&c.Header))
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}

func (c *Container) WriteTempImage(vaultKey []byte) (string, error) {
	plaintext, err := c.Decrypt(vaultKey)
	if err != nil {
		return "", err
	}
	defer crypto2.Memzero(plaintext)

	f, err := os.CreateTemp("", "yukvault-"+uuid.NewString()+"-*.img")
	if err != nil {
		return "", fmt.Errorf("create temp image: %w", err)
	}
	imagePath := f.Name()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		_ = os.Remove(imagePath)
		return "", fmt.Errorf("chmod temp image: %w", err)
	}
	if _, err := f.Write(plaintext); err != nil {
		f.Close()
		_ = os.Remove(imagePath)
		return "", fmt.Errorf("write temp image: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(imagePath)
		return "", fmt.Errorf("sync temp image: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(imagePath)
		return "", fmt.Errorf("close temp image: %w", err)
	}
	return imagePath, nil
}

func (c *Container) WriteAtomic() error {
	headerBytes, err := c.Header.MarshalBinary()
	if err != nil {
		return fmt.Errorf("serialize header: %w", err)
	}
	dir := filepath.Dir(c.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}
	f, err := os.CreateTemp(dir, filepath.Base(c.Path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp vault: %w", err)
	}
	tmpPath := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temp vault: %w", err)
	}

	if _, err := f.Write(headerBytes); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := f.Write(c.Ciphertext); err != nil {
		return fmt.Errorf("write ciphertext: %w", err)
	}
	if c.Trailer != nil {
		trailerBytes, err := c.Trailer.MarshalBinary()
		if err != nil {
			return fmt.Errorf("serialize trailer: %w", err)
		}
		if _, err := f.Write(trailerBytes); err != nil {
			return fmt.Errorf("write trailer: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync vault file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp vault: %w", err)
	}
	if err := os.Rename(tmpPath, c.Path); err != nil {
		return fmt.Errorf("rename vault file: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync vault dir: %w", err)
	}
	return nil
}

func (c *Container) EncryptWithVaultKey(vaultKey []byte, plaintext []byte) error {
	if len(vaultKey) != 32 {
		return fmt.Errorf("vault key must be 32 bytes")
	}
	var key [32]byte
	copy(key[:], vaultKey)
	c.Header.PlaintextSize = uint64(len(plaintext))
	nonce, ciphertext, tag, err := crypto2.Seal(key, plaintext, AAD(&c.Header))
	if err != nil {
		return fmt.Errorf("encrypt payload: %w", err)
	}
	c.Header.Nonce = nonce
	c.Header.GCMTag = tag
	c.Ciphertext = ciphertext
	return nil
}

func GenerateRecoveryKey() (string, []byte, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", nil, err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", nil, err
	}
	return mnemonic, entropy, nil
}

func (c *Container) AttachRecoveryKey(vaultKey []byte) (string, []byte, error) {
	mnemonic, entropy, err := GenerateRecoveryKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate recovery key: %w", err)
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", nil, fmt.Errorf("generate recovery salt: %w", err)
	}
	stretched := crypto2.StretchRecoveryKey(hex.EncodeToString(entropy), salt)
	recHash := crypto2.HashRecoveryKey(stretched[:], salt, crypto2.ArgonTime, crypto2.ArgonMemory, uint32(crypto2.ArgonThreads))
	var stretchedKey [32]byte
	copy(stretchedKey[:], stretched[:])
	nonce, cipherText, tag, err := crypto2.Seal(stretchedKey, vaultKey, []byte(recoveryAAD))
	if err != nil {
		return "", nil, fmt.Errorf("encrypt recovery payload: %w", err)
	}
	trailer := NewRecoveryTrailer()
	trailer.Argon2Salt = salt
	trailer.Argon2Time = crypto2.ArgonTime
	trailer.Argon2Memory = crypto2.ArgonMemory
	trailer.Argon2Threads = uint32(crypto2.ArgonThreads)
	trailer.RecovKeyHash = recHash
	trailer.RecovNonce = nonce
	trailer.RecovTag = tag
	copy(trailer.RecovCipher[:], cipherText)
	c.Trailer = &trailer
	c.Header.Flags |= FlagRecovery
	return mnemonic, entropy, nil
}

func (c *Container) VerifyRecoveryKey(stretched [32]byte) error {
	if c.Trailer == nil {
		return fmt.Errorf("missing recovery trailer")
	}
	hash := crypto2.HashRecoveryKey(stretched[:], c.Trailer.Argon2Salt, c.Trailer.Argon2Time, c.Trailer.Argon2Memory, c.Trailer.Argon2Threads)
	if !bytes.Equal(hash[:], c.Trailer.RecovKeyHash[:]) {
		return fmt.Errorf("recovery key verification failed")
	}
	return nil
}

func (c *Container) RecoverVaultKeyInto(stretched [32]byte, dst []byte) error {
	if c.Trailer == nil {
		return fmt.Errorf("missing recovery trailer")
	}
	plain, err := crypto2.Open(stretched, c.Trailer.RecovNonce, c.Trailer.RecovCipher[:], c.Trailer.RecovTag, []byte(recoveryAAD))
	if err != nil {
		return fmt.Errorf("decrypt recovery trailer: %w", err)
	}
	defer crypto2.Memzero(plain)
	copy(dst, plain)
	return nil
}

func FormatRecoveryMnemonic(mnemonic string) string {
	words := strings.Fields(mnemonic)
	var b strings.Builder
	b.WriteString("============================================================\n")
	b.WriteString("  RECOVERY KEY — STORE THIS IN A SAFE PLACE\n")
	b.WriteString("  You will need this if your YubiKey is lost or damaged.\n")
	b.WriteString("============================================================\n\n")
	for i := 0; i < len(words); i += 6 {
		end := min(i+6, len(words))
		b.WriteString("  ")
		b.WriteString(strings.Join(words[i:end], " "))
		b.WriteString("\n")
	}
	b.WriteString("\n============================================================\n")
	return b.String()
}

func DefaultStatePath() string {
	cfg, err := os.UserConfigDir()
	if err != nil {
		if home, homeErr := os.UserHomeDir(); homeErr == nil && home != "" {
			return filepath.Join(home, ".config", "yukvault", "mounts.json")
		}
		return filepath.Join(os.TempDir(), "yukvault-mounts.json")
	}
	return filepath.Join(cfg, "yukvault", "mounts.json")
}

func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &State{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state file: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse state file: %w", err)
	}
	return &state, nil
}

func AddMount(path string, info mount.MountInfo) error {
	state, err := LoadState(path)
	if err != nil {
		return err
	}
	filtered := state.Mounts[:0]
	for _, existing := range state.Mounts {
		if absEqual(existing.VaultPath, info.VaultPath) && absEqual(existing.MountPoint, info.MountPoint) {
			continue
		}
		filtered = append(filtered, existing)
	}
	state.Mounts = append(filtered, MountedEntry{
		VaultPath:  info.VaultPath,
		ImagePath:  info.ImagePath,
		MountPoint: info.MountPoint,
		OpenedAt:   time.Now().UTC(),
	})
	return saveState(path, state)
}

func AddVerifiedMount(path string, entry MountedEntry) error {
	state, err := LoadState(path)
	if err != nil {
		return err
	}
	filtered := state.Mounts[:0]
	for _, existing := range state.Mounts {
		if absEqual(existing.VaultPath, entry.VaultPath) && absEqual(existing.MountPoint, entry.MountPoint) {
			continue
		}
		filtered = append(filtered, existing)
	}
	state.Mounts = append(filtered, entry)
	return saveState(path, state)
}

func RemoveMount(path string, entry MountedEntry) error {
	state, err := LoadState(path)
	if err != nil {
		return err
	}
	filtered := state.Mounts[:0]
	for _, current := range state.Mounts {
		if current.VaultPath == entry.VaultPath && current.MountPoint == entry.MountPoint {
			continue
		}
		filtered = append(filtered, current)
	}
	state.Mounts = filtered
	return saveState(path, state)
}

func FindMount(path, vaultPath, mountPoint string) (MountedEntry, error) {
	state, err := LoadState(path)
	if err != nil {
		return MountedEntry{}, err
	}
	for _, entry := range state.Mounts {
		if vaultPath != "" && absEqual(entry.VaultPath, vaultPath) {
			return entry, nil
		}
		if mountPoint != "" && absEqual(entry.MountPoint, mountPoint) {
			return entry, nil
		}
	}
	return MountedEntry{}, fmt.Errorf("mounted vault not found")
}

func saveState(path string, state *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize state: %w", err)
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	return nil
}

func createFilesystemImage(sizeBytes int64, fsType string) ([]byte, string, error) {
	tmp, err := os.CreateTemp("", "yukvault-*.img")
	if err != nil {
		return nil, "", fmt.Errorf("create temp image file: %w", err)
	}
	imagePath := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = shredFile(imagePath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return nil, "", fmt.Errorf("chmod temp image: %w", err)
	}
	if err := tmp.Truncate(sizeBytes); err != nil {
		return nil, "", fmt.Errorf("truncate temp image: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, "", fmt.Errorf("close temp image: %w", err)
	}
	if err := formatImage(imagePath, fsType); err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(imagePath)
	if err != nil {
		return nil, "", fmt.Errorf("read formatted image: %w", err)
	}
	return data, imagePath, nil
}

func formatImage(imagePath, fsType string) error {
	var cmd *exec.Cmd
	switch fsType {
	case "ext4":
		cmd = exec.Command("mkfs.ext4", "-L", "yukvault", imagePath)
	case "exfat":
		cmd = exec.Command("mkfs.exfat", imagePath)
	default:
		return fmt.Errorf("unsupported filesystem type: %s", fsType)
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("format image with %s: %w (%s)", fsType, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func shredFile(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat temp image: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open temp image for shred: %w", err)
	}
	defer f.Close()
	zeroBlock := make([]byte, 4096)
	remaining := info.Size()
	for remaining > 0 {
		chunk := int64(len(zeroBlock))
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := f.Write(zeroBlock[:chunk]); err != nil {
			return fmt.Errorf("zero temp image: %w", err)
		}
		remaining -= chunk
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync shredded image: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove temp image: %w", err)
	}
	return nil
}

func absEqual(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return aa == bb
}

func Shred(path string) error {
	return shredFile(path)
}

func BuildMountedEntry(vaultPath string, info mount.MountInfo, container *Container) (MountedEntry, error) {
	if container == nil {
		return MountedEntry{}, fmt.Errorf("container is required")
	}
	imagePath, err := filepath.Abs(info.ImagePath)
	if err != nil {
		return MountedEntry{}, fmt.Errorf("resolve image path: %w", err)
	}
	mountPoint, err := filepath.Abs(info.MountPoint)
	if err != nil {
		return MountedEntry{}, fmt.Errorf("resolve mount point: %w", err)
	}
	vaultPath, err = filepath.Abs(vaultPath)
	if err != nil {
		return MountedEntry{}, fmt.Errorf("resolve vault path: %w", err)
	}
	stat, err := os.Stat(imagePath)
	if err != nil {
		return MountedEntry{}, fmt.Errorf("stat temp image: %w", err)
	}
	return MountedEntry{
		VaultPath:      vaultPath,
		ImagePath:      imagePath,
		MountPoint:     mountPoint,
		OpenedAt:       time.Now().UTC(),
		VaultID:        hex.EncodeToString(container.Header.VaultID[:]),
		CredIDHash:     hex.EncodeToString(container.Header.CredIDHash[:]),
		PlaintextSize:  container.Header.PlaintextSize,
		ExpectedImgLen: stat.Size(),
	}, nil
}

func ValidateMountedEntry(entry MountedEntry, container *Container) error {
	if container == nil {
		return fmt.Errorf("container is required")
	}
	if entry.ImagePath == "" {
		return fmt.Errorf("mounted entry is missing image path")
	}
	if entry.VaultID != "" && entry.VaultID != hex.EncodeToString(container.Header.VaultID[:]) {
		return fmt.Errorf("mounted entry vault id does not match container")
	}
	if entry.CredIDHash != "" && entry.CredIDHash != hex.EncodeToString(container.Header.CredIDHash[:]) {
		return fmt.Errorf("mounted entry credential hash does not match container")
	}
	if entry.PlaintextSize != 0 && entry.PlaintextSize != container.Header.PlaintextSize {
		return fmt.Errorf("mounted entry plaintext size does not match container")
	}
	imagePath, err := filepath.Abs(entry.ImagePath)
	if err != nil {
		return fmt.Errorf("resolve image path: %w", err)
	}
	tmpDir := filepath.Clean(os.TempDir()) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(imagePath)+string(os.PathSeparator), tmpDir) {
		return fmt.Errorf("mounted image path is outside the system temp directory")
	}
	base := filepath.Base(imagePath)
	if !strings.HasPrefix(base, "yukvault-") || !strings.HasSuffix(base, ".img") {
		return fmt.Errorf("mounted image path does not match expected yukvault temp image naming")
	}
	info, err := os.Lstat(imagePath)
	if err != nil {
		return fmt.Errorf("stat mounted image path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("mounted image path must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("mounted image path must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("mounted image path must have 0600 permissions")
	}
	if entry.ExpectedImgLen != 0 && info.Size() != entry.ExpectedImgLen {
		return fmt.Errorf("mounted image size changed unexpectedly")
	}
	if info.Size() <= 0 {
		return fmt.Errorf("mounted image file is empty")
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("sync parent dir: %w", err)
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
