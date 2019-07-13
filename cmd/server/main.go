package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	utilities "github.com/devgenie/miniature/internal/common"
	"github.com/devgenie/miniature/internal/miniature"
)

func startServer(serverConfig string) {
	config := new(miniature.ServerConfig)
	if serverConfig != "" {
		err := utilities.FileToYaml(serverConfig, config)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		config.CertificatesDirectory = "/etc/miniature/certs"
		config.Network = "10.2.0.0/24"
		config.ListeningPort = 4321
	}

	log.Println(config.Metadata.Country)
	server := new(miniature.Server)
	server.Run(*config)
}

func main() {
	runFlag := flag.NewFlagSet("run", flag.ExitOnError)
	serverConfigFlag := runFlag.String("config", "/etc/miniature/config.yml", "Server configuration file")

	clientConfig := flag.NewFlagSet("newclient", flag.ExitOnError)
	configFile := clientConfig.String("config", "/etc/miniature/config.yml", "Server Configuration File")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "newclient":
			serverConfig := new(miniature.ServerConfig)
			if len(os.Args) == 3 {
				clientConfig.Parse(os.Args[2:])
				serverConfigYamlPath := *configFile
				err := utilities.FileToYaml(serverConfigYamlPath, serverConfig)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				serverConfig.CertificatesDirectory = "/etc/miniature/certs"
				serverConfig.Network = "10.2.0.0/24"
			}
			server := new(miniature.Server)
			server.Config = *serverConfig
			config, err := server.CreateClientConfig()
			if err != nil {
				log.Fatal(err)
				break
			}
			fmt.Println(config)
		case "run":
			if len(os.Args) == 3 {
				runFlag.Parse(os.Args[2:])
				startServer(*serverConfigFlag)
			} else {
				startServer("")
			}
		default:
			flag.Usage()
		}
	} else {
		startServer("")
	}
}
