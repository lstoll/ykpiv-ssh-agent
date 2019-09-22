package main

import (
	"fmt"

	"pault.ag/go/ykpiv"
)

var (
	managementKey = []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	defaultPIN = "123456"
)

func getInstance(reader string, opts *ykpiv.Options) (*ykpiv.Yubikey, error) {
	if opts == nil {
		opts = &ykpiv.Options{}
	}
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
	yk, err := ykpiv.New(*opts)
	if err != nil {
		return nil, fmt.Errorf("error opening reader %s: %w", reader, err)
	}

	return yk, nil
}
