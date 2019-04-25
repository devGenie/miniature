package main

import (
	"fmt"
	"log"
	"net"

	"github.com/songgao/water"
)

type tun struct {
	ifce        *water.Interface
	name        string
	ip          *net.IP
	localSubnet *net.IPNet
	subnetMast  *net.IPMask
	mtu         string
}

func Create() (*tun, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	tunInterface, err := water.New(config)
	if err != nil {
		return nil, err
	}
	ifce := tun{ifce: tunInterface}
	return &ifce, nil
}

func Configure(tun *tun, addr *net.IP, mtu string) (*tun, error) {
	command := fmt.Sprintf("link set dev %s mtu %s", tun.name, mtu)
	err := RunCommand("ip", command)
	if err != nil {
		log.Fatalf("Error configuring interface %, message: %s \n", tun.name, err)
		return nil, err
	}

	tun.mtu = mtu
	command = fmt.Sprintf("add add dev %s local %s peer %s", tun.name, addr.String(), addr.String())
	err = RunCommand("ip", command)
	if err != nil {
		log.Fatalf("Error configuring interface %, message: %s \n", tun.name, err)
		return nil, err
	}
	tun.ip = addr
	command = fmt.Sprintf("link set dev %s up", tun.name)
	err = RunCommand("ip", command)
	if err != nil {
		log.Fatalf("Error configuring interface %, message: %s \n", tun.name, err)
		return nil, err
	}
	return tun, nil
}
