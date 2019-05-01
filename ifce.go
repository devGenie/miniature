package main

import (
	"fmt"
	"log"
	"net"

	"github.com/songgao/water"
)

type Tun struct {
	ifce       *water.Interface
	name       string
	ip         *net.IP
	remote     *net.IP
	subnetMask *net.IPMask
	mtu        string
}

func newInterface() (*Tun, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	tunInterface, err := water.New(config)
	if err != nil {
		return nil, err
	}
	ifce := Tun{ifce: tunInterface}
	return &ifce, nil
}

func (tun *Tun) Configure(ifceAddr *net.IP, remote *net.IP, mtu string) error {
	ipaddr := ifceAddr.String()
	command := fmt.Sprintf("link set dev %s mtu %s", tun.ifce.Name(), mtu)
	err := RunCommand("ip", command)
	if err != nil {
		log.Fatalf("Error configuring interface %s, message: %s \n", tun.ifce.Name(), err)
		return err
	}

	tun.mtu = mtu
	command = fmt.Sprintf("add add dev %s local %s peer %s", tun.ifce.Name(), ipaddr, remote.String())
	err = RunCommand("ip", command)
	if err != nil {
		log.Fatalf("Error configuring interface %s, message: %s \n", tun.ifce.Name(), err)
		return err
	}

	command = fmt.Sprintf("link set dev %s up", tun.ifce.Name())
	err = RunCommand("ip", command)
	if err != nil {
		log.Printf("Error configuring interface %s, message: %s \n", tun.ifce.Name(), err)
		return err
	}
	tun.ip = ifceAddr
	return nil
}
