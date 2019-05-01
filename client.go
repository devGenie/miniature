package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"golang.org/x/net/ipv4"
)

type Client struct {
	ifce *Tun
	conn *net.UDPConn
}

func NewClient(server string) {
	_, err := newInterface()
	if err != nil {
		log.Printf("Failed to create interface")
	}

	client := new(Client)
	client.listen(server, "4321")
	defer client.conn.Close()
	//incoming := make(chan []byte)
	sessionStart := make(chan string)
	var waiter sync.WaitGroup
	waiter.Add(2)
	go client.handleIncomingConnections(&waiter, sessionStart)
	go client.handleOutgoingConnections(&waiter, sessionStart)
	client.greetServer()

	waiter.Wait()
}

func (client *Client) listen(server string, port string) {
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", server, port))
	if err != nil {
		log.Println("Failed to establish connection with the server")
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Printf("Failed to connect to %s", server)
	}
	client.conn = conn
}

func (client *Client) greetServer() {
	packetHeader := PacketHeader{Flag: HANDSHAKE}
	packet := Packet{PacketHeader: packetHeader, Payload: make([]byte, 0)}

	encodedData, err := encode(&packet)

	if err != nil {
		log.Printf("An error occured while encoding data returned \n Error: %s \n", err)
		return
	}

	client.conn.Write(encodedData)

}

func (client *Client) handleServerGreeting(packet []byte) {
	fmt.Println("Handling Server greeting")
	fmt.Println("Configuring new tun interface")
	ifce, err := newInterface()
	if err != nil {
		log.Println("Error creating tun interface")
	}

	ipAddr := new(Addr)
	err = decode(ipAddr, packet)

	if err != nil {
		log.Printf("An error occurred trying to decode data from the server \t Error: %s \n", err)
		return
	}
	err = ifce.Configure(ipAddr.IpAddr, ipAddr.Gateway, "1400")
	if err != nil {
		log.Printf("Error: %s \n", err)
	}
	fmt.Println("Client has been assigned ", ipAddr.IpAddr)
	fmt.Println("Sending reply to server")
	client.ifce = ifce

	peer := new(Peer)
	peer.MacAddress = "randomMacAddress"
	peer.IP = ifce.ip.String()

	encodedPeer, err := encode(&peer)

	if err != nil {
		log.Printf("An error occured while encording peer data \t Error : %s \n", err)
		return
	}

	packetHeader := PacketHeader{Flag: CLIENT_CONFIGURATION}
	sendPacket := Packet{PacketHeader: packetHeader, Payload: encodedPeer}

	encodedPacket, err := encode(&sendPacket)

	if err != nil {
		log.Printf("An error occured while encording peer data \t Error : %s \n", err)
		return
	}

	client.conn.Write(encodedPacket)

}

func (client *Client) handleIncomingConnections(waiter *sync.WaitGroup, sessionStart chan string) {
	defer waiter.Done()
	inputBytes := make([]byte, 2048)
	packet := new(Packet)

	for {
		length, err := client.conn.Read(inputBytes)
		if err != nil || length == 0 {
			fmt.Printf("Error : %s \n", err)
			continue
		}

		fmt.Printf("Recieved %s bytes \n", length)
		err = decode(packet, inputBytes)
		if err != nil {
			log.Printf("Error decoding data from the server \t Error : %s \n", err)
			continue
		}
		packetHeader := packet.PacketHeader
		headerFlag := packetHeader.Flag

		switch headerFlag {
		case HANDSHAKE_ACCEPTED:
			client.handleServerGreeting(packet.Payload)
		case SESSION_ACCEPTED:
			//client.handleOutgoingConnections()
			fmt.Printf("Starting session, MTU of link is %s \n", client.ifce.mtu)
			sessionStart <- client.ifce.mtu
		default:
			fmt.Println("Expected headers not found")
		}
	}
}

func (client *Client) handleOutgoingConnections(waiter *sync.WaitGroup, sessionStart chan string) {
	defer waiter.Done()
	fmt.Println("Handling outgoing connection")
	mtu := <-sessionStart
	packetSize, err := strconv.Atoi(mtu)

	if err != nil {
		fmt.Printf("Error converting string to integer %s", err)
	}

	packetSize = packetSize - 400
	buffer := make([]byte, packetSize)
	for {
		length, err := client.ifce.ifce.Read(buffer)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if length > -4 {
			header, err := ipv4.ParseHeader(buffer[:length])
			if err != nil {
				fmt.Println(err)
				continue
			}
			packetHeader := PacketHeader{Flag: SESSION}
			sendPacket := Packet{PacketHeader: packetHeader, Payload: buffer[:length]}
			encodedPacket, err := encode(sendPacket)

			if err != nil {
				log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
				return
			}
			fmt.Printf("Sending %d bytes to %s \n", header.Len, header.Dst)
			client.conn.Write(encodedPacket)
		}
	}
}
