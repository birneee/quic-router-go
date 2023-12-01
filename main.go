package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/birneee/quic-router-go/router"
	"github.com/urfave/cli/v2"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
)

const DefaultPort = 18080

func main() {
	var doOnStop []func()

	var secret *[32]byte
	var defaultServerAddr netip.AddrPort

	app := &cli.App{
		Name:  "quic-router-go",
		Usage: "A QUIC router",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "cpu-profile",
				Usage: "output path of prof file",
				Action: func(context *cli.Context, fileName string) error {
					w, err := os.Create(fileName)
					if err != nil {
						return err
					}
					err = pprof.StartCPUProfile(w)
					if err != nil {
						return err
					}
					doOnStop = append(doOnStop, func() {
						pprof.StopCPUProfile()
						_ = w.Close()
					})
					return nil
				},
			},
			&cli.StringFlag{
				Name:  "key",
				Usage: "key for connection ID and extension header protection; value must be 32 byte and base64 encoded; if not set a random key is generated",
				Value: "",
				Action: func(ctx *cli.Context, s string) error {
					key, err := base64.StdEncoding.DecodeString(s)
					if err != nil {
						return fmt.Errorf("failed to parse key: %s", err)
					}
					if len(key) != 32 {
						return fmt.Errorf("failed to parse key: must be 32 byte")
					}
					secret = (*[32]byte)(key)
					return nil
				},
			},
			&cli.UintFlag{
				Name:  "port",
				Usage: "port to listen on",
				Value: DefaultPort,
			},
		},
		Action: func(ctx *cli.Context) error {
			addr := netip.AddrPortFrom(netip.MustParseAddr("::"), uint16(ctx.Uint("port")))
			conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
			if err != nil {
				return err
			}
			fmt.Printf("listen on %s\n", addr.String())
			if secret == nil {
				secret = (*[32]byte)(make([]byte, 32))
				rand.Read(secret[:])
				fmt.Printf("generated key: %s\n", base64.StdEncoding.EncodeToString(secret[:]))
			}
			r, err := router.NewRouter(conn, *secret, defaultServerAddr, &router.Config{})
			if err != nil {
				return err
			}
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM, os.Kill)
			go func() {
				<-c
				r.Stop(nil)
			}()
			<-r.Context().Done()
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
	for _, d := range doOnStop {
		d()
	}
}
