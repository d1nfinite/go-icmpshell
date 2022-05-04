package main

import (
	"github.com/d1nfinite/go-icmpshell/server"
	"github.com/urfave/cli"
	"log"
	"os"
)

var (
	app = &cli.App{
		Name:  "go-icmpshell",
		Usage: "go-icmpshell",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "token",
				Usage: "Handshake token",
				Value: "go-icmpshell",
			},
		},
		Action: func(c *cli.Context) error {
			s, err := server.NewServer(server.WithToken([]byte(c.String("token"))))
			if err != nil {
				log.Fatal(err)
			}

			go s.ListenICMP()
			err = s.StartupShell()
			if err != nil {
				log.Fatal(err)
			}

			return nil
		},
	}
)

func main() {
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
