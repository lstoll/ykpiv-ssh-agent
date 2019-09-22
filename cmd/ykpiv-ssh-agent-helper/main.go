package main

import (
	"os"

	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	var (
		app = kingpin.New("ykpiv-ssh-agent-helper", "Helper tool for interacting with the PIV applet on yubikeys")
	)

	readersC, readers := readersCmd(app)
	initializeC, initialize := initializeCmd(app)

	var err error

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case readersC.FullCommand():
		err = readers()
	case initializeC.FullCommand():
		err = initialize()
	}

	app.FatalIfError(err, "Command failed")
}
