package main

import (
	"flag"
)

func main() {
	remote := flag.String("remote", " ", "Remote IP address")
	serverType := flag.String("type", "server", "vpn_type")
	flag.Parse()

	if *serverType == "server" {
		NewServer("10.2.0.2/24")
	} else {
		NewClient(*remote)
	}
}
