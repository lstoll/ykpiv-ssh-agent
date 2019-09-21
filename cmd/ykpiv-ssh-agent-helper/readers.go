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
			fmt.Printf("%s\n", r)
		}
		return nil
	}
}
