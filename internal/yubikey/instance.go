package yubikey

import (
	"encoding/hex"
	"fmt"

	"pault.ag/go/ykpiv"
)

// GetForRead returns a Yubikey instance suitible for read-only operations only.
func GetForRead(reader string) (*ykpiv.Yubikey, error) {
	return getInstance(reader, ykpiv.Options{})
}

// GetForRead returns a Yubikey instance suitible for read/signing operations.
func GetForUsage(reader, pin string) (*ykpiv.Yubikey, error) {
	inst, err := getInstance(reader, ykpiv.Options{
		PIN: &pin,
	})
	if err != nil {
		return nil, err
	}
	if err := inst.Login(); err != nil {
		return nil, fmt.Errorf("failed logging in to yubikey. Check PIN?: %w", err)
	}
	return inst, nil
}

// GetForManagement returns a Yubikey instance suitible for key management.
func GetForManagement(reader, managementKey string) (*ykpiv.Yubikey, error) {
	mb, err := hex.DecodeString(managementKey)
	if err != nil {
		return nil, fmt.Errorf("failed decoding management key %s: %w", managementKey, err)
	}
	inst, err := getInstance(reader, ykpiv.Options{
		ManagementKey: mb,
	})
	if err != nil {
		return nil, err
	}
	if err := inst.Authenticate(); err != nil {
		return nil, fmt.Errorf("failed authenticating yubikey. Check management key?: %w", err)
	}
	return inst, nil
}

func getInstance(reader string, opts ykpiv.Options) (*ykpiv.Yubikey, error) {
	if reader == "" {
		rdrs, err := ykpiv.Readers()
		if err != nil {
			return nil, fmt.Errorf("failed to list readers in system: %w", err)
		}
		if len(rdrs) != 1 {
			return nil, fmt.Errorf("expected one reader in the system, found %d", len(rdrs))
		}
		reader = rdrs[0]
	}
	opts.Reader = reader
	yk, err := ykpiv.New(opts)
	if err != nil {
		return nil, fmt.Errorf("error opening reader %s: %w", reader, err)
	}

	return yk, nil
}
