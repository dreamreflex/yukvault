package yubikey

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	libfido2 "github.com/keys-pub/go-libfido2"
)

type DeviceInfo struct {
	Path         string
	Manufacturer string
	Product      string
}

func ListDevices() ([]DeviceInfo, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("enumerate FIDO2 devices: %w", err)
	}
	devices := make([]DeviceInfo, 0, len(locs))
	for _, loc := range locs {
		devices = append(devices, DeviceInfo{
			Path:         loc.Path,
			Manufacturer: loc.Manufacturer,
			Product:      loc.Product,
		})
	}
	return devices, nil
}

func SelectDevice(devicePath string) (DeviceInfo, error) {
	if devicePath != "" {
		return DeviceInfo{Path: devicePath}, nil
	}
	devices, err := ListDevices()
	if err != nil {
		return DeviceInfo{}, err
	}
	if len(devices) == 0 {
		return DeviceInfo{}, fmt.Errorf("no YubiKey detected")
	}
	if len(devices) == 1 {
		return devices[0], nil
	}
	for idx, dev := range devices {
		fmt.Fprintf(os.Stderr, "[%d] %s %s (%s)\n", idx+1, dev.Manufacturer, dev.Product, dev.Path)
	}
	fmt.Fprint(os.Stderr, "Select YubiKey: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("read device selection: %w", err)
	}
	choice, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || choice < 1 || choice > len(devices) {
		return DeviceInfo{}, fmt.Errorf("invalid device selection")
	}
	return devices[choice-1], nil
}

func MakeCredential(devicePath, pin string, clientDataHash []byte, vaultID [32]byte) ([]byte, error) {
	dev, err := libfido2.NewDevice(devicePath)
	if err != nil {
		return nil, fmt.Errorf("open FIDO2 device: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Touch your YubiKey now…")
	attestation, err := dev.MakeCredential(
		clientDataHash,
		libfido2.RelyingParty{
			ID:   "yukvault",
			Name: "YubiKey Vault",
		},
		libfido2.User{
			ID:   append([]byte(nil), vaultID[:8]...),
			Name: "vault",
		},
		libfido2.ES256,
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("make FIDO2 credential: %w", err)
	}
	return append([]byte(nil), attestation.CredentialID...), nil
}

func GetHMACSecret(devicePath, pin string, credentialID, clientDataHash, hmacSalt []byte) ([]byte, error) {
	if len(hmacSalt) != 32 {
		return nil, fmt.Errorf("hmac salt must be exactly 32 bytes")
	}
	fmt.Fprintln(os.Stderr, "Touch your YubiKey now…")
	dev, err := libfido2.NewDevice(devicePath)
	if err != nil {
		return nil, fmt.Errorf("open FIDO2 device: %w", err)
	}
	assertion, err := dev.Assertion(
		"yukvault",
		clientDataHash,
		[][]byte{credentialID},
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			HMACSalt:   hmacSalt,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get FIDO2 assertion: %w", err)
	}
	if len(assertion.HMACSecret) != 32 {
		return nil, fmt.Errorf("unexpected hmac-secret length: got %d want 32", len(assertion.HMACSecret))
	}
	return append([]byte(nil), assertion.HMACSecret...), nil
}
