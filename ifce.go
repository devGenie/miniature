package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

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

func getDefaultGateway() (ifaceName string, gateway string, err error) {
	routeFile, err := os.Open("/proc/net/route")
	if err != nil {
		log.Println("Error reading /proc/net/route")
		return "", "", err
	}
	defer routeFile.Close()

	scanner := bufio.NewScanner(routeFile)

	lastline := 0
	for scanner.Scan() {
		lastline++
		if lastline == 2 {
			currentLine := scanner.Text()
			splitEntries := strings.Split(currentLine, "\t")
			ifaceName = splitEntries[0]
			gateway = splitEntries[2]
			break
		}
	}

	// reverse gateway address
	decodedGateway, err := hex.DecodeString(gateway)

	if len(decodedGateway) != net.IPv4len {
		log.Println("Error : This is not a valid IP address")
		return "", "", fmt.Errorf("Invalid IPv4 address")
	}
	ipAddr := net.IP([]byte{decodedGateway[3], decodedGateway[2], decodedGateway[1], decodedGateway[0]})
	gateway = ipAddr.String()
	return ifaceName, gateway, nil
}
