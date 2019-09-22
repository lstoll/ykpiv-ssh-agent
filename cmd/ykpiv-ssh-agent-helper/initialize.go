package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"
	"pault.ag/go/ykpiv"
)

func initializeCmd(app *kingpin.Application) (*kingpin.CmdClause, func() error) {
	var (
		initialize = app.Command("initialize", "Init slot 9a for SSH operations")

		reader        = initialize.Flag("reader", "Yubikey to use. Defaults to the only key in the system, errors if <> 1 present").String()
		force         = initialize.Flag("force", "Initialize even if the slot is already initialized. This is destructive").Bool()
		managementKey = initialize.Flag("management-key", "Management key for the PIV applet").Default("010203040506070801020304050607080102030405060708").String()
	)

	return initialize, func() error {
		mb, err := hex.DecodeString(*managementKey)
		if err != nil {
			return fmt.Errorf("failed decoding management key %s: %w", *managementKey, err)
		}
		pin := "123456"
		puk := "12345678"
		opts := ykpiv.Options{
			ManagementKey: mb,
			PIN:           &pin,
			PUK:           &puk,
		}
		yk, err := getInstance(*reader, &opts)
		if err != nil {
			return err
		}
		defer yk.Close()
		if err := yk.Authenticate(); err != nil {
			return fmt.Errorf("failed authenticating yubikey. Check management key?: %w", err)
		}

		_, err = yk.Slot(ykpiv.Authentication)
		yerr, _ := err.(ykpiv.Error)
		if err != nil && yerr.Code != -7 {
			return fmt.Errorf("unknown error occured: %w", err)
		}
		if err == nil && !*force {
			return fmt.Errorf("slot appears initialized, and force not specified")
		}

		// TODO - proper policies
		sl, err := yk.GenerateRSAWithPolicies(ykpiv.Authentication, 2048, ykpiv.PinPolicyNever, ykpiv.TouchPolicyNever)
		if err != nil {
			return fmt.Errorf("failed to generate new RSA key: %w", err)
		}

		// We don't strictly need a cert here, but the PIV applet generally
		// expects it so it's easier to create a more-or-less dummy cert to make
		// it happy.
		cer, err := genCert(sl)
		if err != nil {
			return err
		}

		if err := sl.Update(*cer); err != nil {
			return fmt.Errorf("failed to set cert on slot: %w", err)
		}

		fmt.Println("Slot initialized")
		return nil
	}
}

func genCert(slot *ykpiv.Slot) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert serial: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365 * 10) // 10 years ought to be enough for anyone

	cer := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "SSH",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}

	dc, err := x509.CreateCertificate(rand.Reader, cer, cer, slot.PublicKey, slot)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert: %w", err)
	}

	cer, err = x509.ParseCertificate(dc)
	if err != nil {
		return nil, fmt.Errorf("failed parsing generated certificate: %w", err)
	}

	return cer, nil
}
