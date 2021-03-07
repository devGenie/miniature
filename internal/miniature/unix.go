package miniature

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/devgenie/miniature/internal/common"
	utilities "github.com/devgenie/miniature/internal/common"
)

// SetDarwinClient sets up IP tables on Darwin hosts
func SetDarwinClient(defaultGWIface string, defaultGWAddr string, tunnelIface string, tunnelIP string, serverIP string) error {
	command := fmt.Sprintf("nat on %s from %s to any -> (%s) \n", defaultGWIface, tunnelIP, defaultGWIface)
	tmpFile, err := ioutil.TempFile(os.TempDir(), "minature-")
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()
	pfctl := []byte(command)
	if _, err = tmpFile.Write(pfctl); err != nil {
		log.Fatal("Failed to write to temporary file", err)
	}

	command = fmt.Sprintf("-f %s", tmpFile.Name())
	err = utilities.RunCommand("pfctl", command)
	if err != nil {
		tmpFile.Close()
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
	command = fmt.Sprintf("./scripts/client/osx_disable_ipv6.sh")
	err = utilities.RunCommand("/bin/sh", command)
	if err != nil {
		tmpFile.Close()
		return err
	}

	return nil
}
