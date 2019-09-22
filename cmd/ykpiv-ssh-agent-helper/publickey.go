package main

import (
	"fmt"

	"golang.org/x/crypto/ssh"
	"gopkg.in/alecthomas/kingpin.v2"
	"pault.ag/go/ykpiv"
)

func publickeyCmd(app *kingpin.Application) (*kingpin.CmdClause, func() error) {
	var (
		publickey = app.Command("public-key", "Print SSH format key")

		reader = publickey.Flag("reader", "Yubikey to use. Defaults to the only key in the system, errors if <> 1 present").String()
	)

	return publickey, func() error {
		opts := ykpiv.Options{
			// PIN:           &pin,
		}
		yk, err := getInstance(*reader, &opts)
		if err != nil {
			return err
		}
		defer yk.Close()

		sl, err := yk.Slot(ykpiv.Authentication)
		if err != nil {
			return fmt.Errorf("couldn't get auth slot: %w", err)
		}

		pk, err := ssh.NewPublicKey(sl.Public())
		if err != nil {
			return fmt.Errorf("failed to create SSH key from slot public key: %w", err)
		}

		fmt.Printf("%s", ssh.MarshalAuthorizedKey(pk))

		return nil
	}
}
