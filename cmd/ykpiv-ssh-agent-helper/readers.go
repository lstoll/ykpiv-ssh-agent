package main

import (
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
	"pault.ag/go/ykpiv"
)

func readersCmd(app *kingpin.Application) (*kingpin.CmdClause, func() error) {
	var (
		readers = app.Command("readers", "List yubikeys in system")
	)

	return readers, func() error {
		rdrs, err := ykpiv.Readers()
		if err != nil {
			return fmt.Errorf("failed to list readers in system: %w", err)
		}
		if len(rdrs) < 1 {
			return fmt.Errorf("No readers found in system")
		}
		for _, r := range rdrs {
			yk, err := ykpiv.New(ykpiv.Options{
				// Verbose: true,
				Reader: r,
			})
			if err != nil {
				return fmt.Errorf("error opening reader %s: %w", r, err)
			}
			defer yk.Close()

			version, err := yk.Version()
			if err != nil {
				return fmt.Errorf("error getting version %s: %w", r, err)
			}

			fmt.Printf("%q Version: %s\n", r, version)
		}
		return nil
	}
}
