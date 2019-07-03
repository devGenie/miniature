package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/robfig/cron"
)

func RunCommand(command, arguments string) error {
	fmt.Printf("Issuing command: %s %s \n", command, arguments)
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
