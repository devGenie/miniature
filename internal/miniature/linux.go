package miniature

import (
	"fmt"
	"strings"

	"github.com/devgenie/miniature/internal/common"
)

// SetUpLinuxClient sets up IP tables on linux
func SetUpLinuxClient(defaultGWIface string, defaultGWAddr string, tunnelIface string, tunnelIP string, serverIP string) error {
	commands := [][]string{
		{"-F", "-t", "nat"}, // Flush the same for the NAT table                                         // Accept all output packets from "interface" in the INPUT chain
		{"-t", "nat", "-A", "POSTROUTING", "-o", tunnelIface, "-j", "SNAT", "--to-source", tunnelIP}, // It says what it does ;)
		{"-P", "FORWARD", "ACCEPT"},
	}

	// Setup IPTables
	for _, command := range commands {
		cmd := strings.Join(command, " ")
		err := common.RunCommand("iptables", cmd)
		if err != nil {
			return err
		}
	}

	// Setup routes
	routes := []common.Route{
		{Destination: "0.0.0.0/1", NextHop: tunnelIP, GWInterface: tunnelIface},
		{Destination: "128.0.0.0/1", NextHop: tunnelIP, GWInterface: tunnelIface},
		{Destination: serverIP, NextHop: defaultGWAddr, GWInterface: defaultGWIface},
	}
	for _, route := range routes {
		err := common.AddRoute(route)
		fmt.Println(err)
		if err != nil {
			return nil
		}
	}
	return nil
}
