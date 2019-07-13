package common

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/robfig/cron"
	"gopkg.in/yaml.v3"
)

func RunCommand(command, arguments string) error {
	log.Printf("Issuing command: %s %s \n", command, arguments)
	commandArguments := strings.Split(arguments, " ")
	cmd := exec.Command(command, commandArguments...)
	err := cmd.Run()
	return err
}

func RunCron(name string, cronString string, cronFunc func()) {
	cronjob := cron.New()
	err := cronjob.AddFunc(cronString, cronFunc)
	if err != nil {
		log.Printf("An error occured setting up %s, err: %s \n", name, err)
		return
	}
	fmt.Printf("Starting %s \n", name)
	cronjob.Start()
	entry := cronjob.Entries()
	fmt.Printf("Cron scheduled to run on %s \n", entry[0].Next)
}

func FileToYaml(filepath string, dataStruct interface{}) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}

	defer file.Close()

	fileData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil
	}

	yaml.Unmarshal(fileData, dataStruct)
	return nil
}

func GetPublicIP(interfaceName string) (ipaddress string, err error) {
	interfaceByname, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", err
	}

	var publicIpAddress string
	ipAddresses, err := interfaceByname.Addrs()
	for _, ipAddr := range ipAddresses {
		addr := ipAddr.(*net.IPNet)
		if !addr.IP.IsLoopback() {
			publicIpAddress = addr.IP.String()
			break
		}
	}

	if len(strings.TrimSpace(publicIpAddress)) > 0 {
		return publicIpAddress, nil
	}
	return "", errors.New("Could not find a public IP address")
}
