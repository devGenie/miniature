package main

import (
	"fmt"
	"os/exec"
	"strings"
)

type Server struct {
	ip               string
	virtualInterface string
}

type Client struct {
	server string
}

func RunCommand(command, arguments string) error {
	fmt.Printf("Issuing command: %s %s \n", command, arguments)
	commandArguments := strings.Split(arguments, " ")
	cmd := exec.Command(command, commandArguments...)
	err := cmd.Run()
	return err
}
