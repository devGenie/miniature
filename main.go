package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"golang.org/x/net/ipv4"
)

func main() {
	remote := flag.String("remote", " ", "Remote IP address")
	flag.Parse()

	server, err := NewServer("10.2.0.2/24")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("Private IP is %s \n", server.tunInterface.ip)
	log.Printf("Interface Name: %s\n", server.tunInterface.ifce.Name())
	log.Printf("Network ubnet is: %s\n", server.network.String())

	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%v", *remote, 4321))
	if nil != err {
		log.Fatalln("Unable to listen on UDP socket")
	}

	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", 4321))

	lstnConn, err := net.ListenUDP("udp", lstnAddr)
	if nil != err {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}
	defer lstnConn.Close()

	ifce := server.tunInterface.ifce

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
			//lstnConn.WriteToUDP(packet[:n], remoteAddr)
			lstnConn.WriteTo(packet[:n], remoteAddr)
		}
	}
}
