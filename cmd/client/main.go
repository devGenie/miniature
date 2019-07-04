package main

import (
	"flag"
	"log"

	utilities "github.com/devgenie/miniature/internal/common"
	"github.com/devgenie/miniature/internal/miniature"
)

func main() {
	configFile := flag.String("config", "/etc/miniature/config.yml", "Client configuration file")
	flag.Parse()

	if *configFile != "" {
		clientConfig := new(miniature.ClientConfig)
		err := utilities.FileToYaml(*configFile, clientConfig)
		if err != nil {
			log.Fatal(err)
		}
		vpnClient := new(miniature.Client)
		vpnClient.Run(*clientConfig)
	} else {
		log.Fatal("Please provide path to config file")
	}
}
