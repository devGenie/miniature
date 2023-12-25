package miniature

import (
	"fmt"
	"log"
	"os"

	"github.com/devgenie/miniature/internal/common"
	utilities "github.com/devgenie/miniature/internal/common"
)

// SetDarwinClient sets up IP tables on Darwin hosts
func SetDarwinClient(defaultGWIface string, defaultGWAddr string, tunnelIface string, tunnelIP string, serverIP string, dnsServer string) error {
	command := fmt.Sprintf("nat on %s from %s to any -> (%s) \n", defaultGWIface, tunnelIP, defaultGWIface)
	tmpFile, err := os.CreateTemp(os.TempDir(), "minature-")
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()
	pfctl := []byte(command)
	_, err = tmpFile.Write(pfctl)
	if err != nil {
		log.Fatal("Failed to write to temporary file", err)
		return err
	}

	command = fmt.Sprintf("-f %s", tmpFile.Name())
	err = utilities.RunCommand("pfctl", command)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// Setup routes
	routes := []common.Route{
		{Destination: "0.0.0.0/0", NextHop: tunnelIP, GWInterface: tunnelIface},
		{Destination: "128.0.0.0/1", NextHop: tunnelIP, GWInterface: tunnelIface},
		{Destination: serverIP, NextHop: defaultGWAddr, GWInterface: defaultGWIface},
	}
	for _, route := range routes {
		common.DeleteRoute(route.Destination)
		err := common.AddRoute(route)
		if err != nil {
			return nil
		}
	}
	// Disable ipv6 on osx
	command = fmt.Sprintf("./scripts/client/osx_setup_interfaces.sh %s", dnsServer)
	err = utilities.RunCommand("/bin/sh", command)
	if err != nil {
		tmpFile.Close()
		return err
	}

	return nil
}
