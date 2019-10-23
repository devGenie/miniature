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

// RunCommand is a wrapper to easily run linux commands
func RunCommand(command, arguments string) error {
	log.Printf("Issuing command: %s %s \n", command, arguments)
	commandArguments := strings.Split(arguments, " ")
	cmd := exec.Command(command, commandArguments...)
	err := cmd.Run()
	return err
}

// RunCron runs cron jobs
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

// FileToYaml unmarshals files to the data stucture specified
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

	err = yaml.Unmarshal(fileData, dataStruct)
	fmt.Println(err)
	return nil
}

// GetPublicIP gets the public ip of the host
func GetPublicIP(interfaceName string) (ipaddress string, err error) {
	interfaceByname, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", err
	}

	var publicIPAddress string
	ipAddresses, err := interfaceByname.Addrs()
	for _, ipAddr := range ipAddresses {
		addr := ipAddr.(*net.IPNet)
		if !addr.IP.IsLoopback() {
			publicIPAddress = addr.IP.String()
			break
		}
	}

	if len(strings.TrimSpace(publicIPAddress)) > 0 {
		return publicIPAddress, nil
	}
	return "", errors.New("Could not find a public IP address")
}
