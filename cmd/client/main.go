package main

import (
	"encoding/gob"
	"flag"
	"log"

	"github.com/aead/ecdh"
	utilities "github.com/devgenie/miniature/internal/common"
	"github.com/devgenie/miniature/internal/miniature"
)

func init() {
	gob.Register(ecdh.Point{})
}

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
		err = vpnClient.Run(*clientConfig)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatal("Please provide path to config file")
	}
}
