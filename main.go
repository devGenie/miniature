package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

func configureInterface(args ...string) {
	cmd := exec.Command("/sbin/ip", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		log.Fatalln("Error configuring ip:", err)
	}
}

func main() {
	local := flag.String("local", " ", "Local IP address")
	remote := flag.String("remote", " ", "Remote IP address")
	flag.Parse()
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Interface Name: %s\n", ifce.Name())
	configureInterface("link", "set", "dev", ifce.Name(), "mtu", "1300")
	configureInterface("addr", "add", *local, "dev", ifce.Name(), "peer", *remote)
	configureInterface("link", "set", "dev", ifce.Name(), "up")

	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%v", *remote, 4321))
	if nil != err {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}

	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", 4321))
	lstnConn, err := net.ListenUDP("udp", lstnAddr)
	if nil != err {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}
	defer lstnConn.Close()

	//recieve packets
	go func() {
		buffer := make([]byte, 2000)
		for {
			n, addr, err := lstnConn.ReadFromUDP(buffer)
			println(n)
			//debug
			header, _ := ipv4.ParseHeader(buffer[:n])
			fmt.Printf("Received %d bytes from %v: %+v\n", n, addr, header)
			if err != nil || n == 0 {
				fmt.Println("Error: ", err)
				continue
			}
			// write to TUN interface
			ifce.Write(buffer[:n])
		}
	}()

	packet := make([]byte, 2000)
	for {
		n, err := ifce.Read(packet)
		if err != nil {
			log.Fatal(err)
			break
		}
		if n > -4 {
			header, err := ipv4.ParseHeader(packet[:n])
			if err != nil {
				fmt.Println(err)
			}
			fmt.Printf("Sending %d bytes to %s \n", n, header.Dst)
			//Send to remote tunnel
			lstnConn.WriteToUDP(packet[:n], remoteAddr)
		}
	}
}
