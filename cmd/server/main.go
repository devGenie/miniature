package main

import (
	"flag"
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

	server := new(miniature.Server)
	server.Run(*config)
}

func main() {
	runFlag := flag.NewFlagSet("run", flag.ExitOnError)
	serverConfigFlag := runFlag.String("config", "/etc/miniature/config.yml", "Server configuration file")

	clientConfig := flag.NewFlagSet("newclient", flag.ExitOnError)
	username := clientConfig.String("username", "", "Username")
	password := clientConfig.String("password", "", "Password")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "newclient":
			if len(os.Args) == 4 {
				err := clientConfig.Parse(os.Args[2:])
				if err != nil {
					log.Fatal(err)
				}

				db := new(miniature.DatabaseObject)
				db.Init()
				vpnUser := new(miniature.User)
				vpnUser.Username = *username
				vpnUser.Password = *password

				err = db.AddUser(vpnUser)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				log.Println(os.Args)
			}
		case "run":
			startServer(*serverConfigFlag)
			if len(os.Args) == 3 {
				log.Println("Running Server")
				err := runFlag.Parse(os.Args[2:])
				if err != nil {
					log.Fatal(err)
				}
				startServer(*serverConfigFlag)
			} else {
				log.Println("Running server with default settings")
				startServer("")
			}
		default:
			flag.Usage()
		}
	} else {
		log.Println("Running server with default config")
		startServer("")
	}
}
