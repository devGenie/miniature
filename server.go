package main

import (
	"log"
	"net"
)

type Server struct {
	tunInterface *Tun
	network      *net.IPNet
}

func NewServer(address string) (*Server, error) {
	ifce, err := newInterface()
	if err != nil {
		log.Print("Failed to create interface")
		return nil, err
	}

	ip, network, err := net.ParseCIDR(address)
	if err != nil {
		log.Print("Failed to create interface")
		return nil, err
	}

	ifce.ip = &ip

	err = ifce.Configure(&ip, "1400")
	if err != nil {
		log.Printf("Error: %s \n", err)
		return nil, err
	}

	server := new(Server)
	server.tunInterface = ifce
	server.network = network
	return server, nil
}
