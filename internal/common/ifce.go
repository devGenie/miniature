package common

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/songgao/water"
)

// Tun represents a Tun interface
type Tun struct {
	Ifce       *water.Interface
	Name       string
	IP         net.IP
	Remote     net.IP
	SubnetMask net.IPMask
	Mtu        string
}

// NewInterface creates a new Tun interface
func NewInterface() (*Tun, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	tunInterface, err := water.New(config)
	if err != nil {
		return nil, err
	}
	ifce := new(Tun)
	ifce.Ifce = tunInterface
	return ifce, nil
}

// Configure configures the Tun interface
func (tun *Tun) Configure(ifceAddr net.IP, remote net.IP, mtu string) error {
	ipaddr := ifceAddr.String()
	if runtime.GOOS == "linux" {
		command := fmt.Sprintf("link set dev %s mtu %s", tun.Ifce.Name(), mtu)
		err := RunCommand("ip", command)
		if err != nil {
			log.Fatalf("Error configuring interface %s, message: %s \n", tun.Ifce.Name(), err)
			return err
		}

		tun.Mtu = mtu
		command = fmt.Sprintf("add add dev %s local %s peer %s", tun.Ifce.Name(), ipaddr, remote.String())
		err = RunCommand("ip", command)
		if err != nil {
			log.Fatalf("Error configuring interface %s, message: %s \n", tun.Ifce.Name(), err)
			return err
		}

		command = fmt.Sprintf("link set dev %s up", tun.Ifce.Name())
		err = RunCommand("ip", command)
		if err != nil {
			log.Printf("Error configuring interface %s, message: %s \n", tun.Ifce.Name(), err)
			return err
		}
	} else if runtime.GOOS == "darwin" {
		command := fmt.Sprintf("%s inet %s %s mtu %s up", tun.Ifce.Name(), ipaddr, remote.String(), mtu)
		if err := exec.Command("ifconfig", command).Run(); err != nil {
			log.Fatalln("Unable to setup interface:", err)
		}
	}

	tun.IP = ifceAddr
	return nil
}

// GetDefaultGateway returns the default gateway on the host
func GetDefaultGateway() (ifaceName string, gateway string, err error) {
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
