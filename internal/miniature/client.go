package miniature

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	utilities "github.com/devgenie/miniature/internal/common"
	"golang.org/x/net/ipv4"
)

type Client struct {
	ifce        *utilities.Tun
	conn        *net.UDPConn
	waiter      sync.WaitGroup
	sessionChan chan string
}

type ClientConfig struct {
	ServerAddress string
	ListeningPort int
	Certificate   string
	PrivateKey    string
}

func NewClient(server string) {
	_, err := utilities.NewInterface()
	if err != nil {
		log.Printf("Failed to create interface")
	}

	client := new(Client)
	client.listen(server, "4321")
	defer client.conn.Close()
	//incoming := make(chan []byte)
	client.sessionChan = make(chan string)
	client.waiter.Add(2)
	go client.handleIncomingConnections()
	go client.handleOutgoingConnections()
	client.greetServer()

	client.waiter.Wait()
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
	fmt.Println("Greeting server")
	packetHeader := utilities.PacketHeader{Flag: utilities.HANDSHAKE}
	packet := utilities.Packet{PacketHeader: packetHeader, Payload: make([]byte, 0)}

	encodedData, err := utilities.Encode(&packet)

	if err != nil {
		log.Printf("An error occured while encoding data returned \n Error: %s \n", err)
		return
	}

	client.conn.Write(encodedData)

}

func (client *Client) handleServerGreeting(packet []byte) {
	fmt.Println("Handling Server greeting")
	fmt.Println("Configuring new tun interface")
	ifce, err := utilities.NewInterface()
	if err != nil {
		log.Println("Error creating tun interface")
	}

	ipAddr := new(utilities.Addr)
	err = utilities.Decode(ipAddr, packet)
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
	peer.IP = ifce.Ip.String()
	encodedPeer, err := utilities.Encode(&peer)
	if err != nil {
		log.Printf("An error occured while encording peer data \t Error : %s \n", err)
		return
	}

	packetHeader := utilities.PacketHeader{Flag: utilities.CLIENT_CONFIGURATION}
	sendPacket := utilities.Packet{PacketHeader: packetHeader, Payload: encodedPeer}

	encodedPacket, err := utilities.Encode(&sendPacket)

	if err != nil {
		log.Printf("An error occured while encording peer data \t Error : %s \n", err)
		return
	}

	client.conn.Write(encodedPacket)
}

func (client *Client) handleIncomingConnections() {
	defer client.waiter.Done()

	inputBytes := make([]byte, 2048)
	packet := new(utilities.Packet)

	for {
		length, err := client.conn.Read(inputBytes)
		if err != nil || length == 0 {
			fmt.Printf("Error : %s \n", err)
			continue
		}

		fmt.Printf("Recieved %s bytes \n", length)
		err = utilities.Decode(packet, inputBytes)
		if err != nil {
			log.Printf("Error decoding data from the server \t Error : %s \n", err)
			continue
		}

		packetHeader := packet.PacketHeader
		headerFlag := packetHeader.Flag

		switch headerFlag {
		case utilities.HANDSHAKE_ACCEPTED:
			client.handleServerGreeting(packet.Payload)
		case utilities.SESSION_ACCEPTED:
			fmt.Printf("Starting session, MTU of link is %s \n", client.ifce.Mtu)

			command := "route delete 0.0.0.0/0"
			err := utilities.RunCommand("ip", command)
			if err != nil {
				log.Printf("Error cdeleting route message: %s \n", err)
			}

			command = fmt.Sprintf("route add 0.0.0.0/0 via %s dev %s", client.ifce.Ip.String(), client.ifce.Ifce.Name())
			err = utilities.RunCommand("ip", command)
			if err != nil {
				log.Printf("Error adding route to 0.0.0.0/0, message: %s \n", err)
			}

			client.sessionChan <- client.ifce.Mtu
			client.StartHeartBeat()
		case utilities.SESSION:
			client.writeToIfce(packet.Payload)
		default:
			fmt.Println("Expected headers not found")
		}
	}
}

func (client *Client) writeToIfce(packet []byte) {
	client.ifce.Ifce.Write(packet)
}

func (client *Client) handleOutgoingConnections() {
	defer client.waiter.Done()

	mtu := <-client.sessionChan
	packetSize, err := strconv.Atoi(mtu)
	fmt.Println("Handling outgoing connection")
	if err != nil {
		fmt.Printf("Error converting string to integer %s", err)
	}

	packetSize = packetSize - 400
	buffer := make([]byte, packetSize)
	for {
		length, err := client.ifce.Ifce.Read(buffer)
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

			packetHeader := utilities.PacketHeader{Flag: utilities.SESSION}
			sendPacket := utilities.Packet{PacketHeader: packetHeader, Payload: buffer[:length]}
			encodedPacket, err := utilities.Encode(sendPacket)
			if err != nil {
				log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
				return
			}

			fmt.Printf("Sending %d bytes to %s \n", len(encodedPacket), header.Dst)
			fmt.Printf("Version %d, Protocol  %d \n", header.Version, header.Protocol)

			client.conn.Write(encodedPacket)
		}
	}
}

func (client *Client) StartHeartBeat() {
	utilities.RunCron("Heartbeat", "0 0/1 * * * *", client.HeartBeat)
}

func (client *Client) HeartBeat() {
	peer := new(Peer)
	peer.IP = client.ifce.Ip.String()
	encodedPeer, err := utilities.Encode(&peer)
	if err != nil {
		log.Printf("An error occured while encording peer data \t Error : %s \n", err)
		return
	}

	packetHeader := utilities.PacketHeader{Flag: utilities.HEARTBEAT}
	sendPacket := utilities.Packet{PacketHeader: packetHeader, Payload: encodedPeer}
	encodedPacket, err := utilities.Encode(sendPacket)
	if err != nil {
		log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
		return
	}

	serverAddress := client.conn.RemoteAddr()
	fmt.Printf("Sending pulse to server at %s \n", serverAddress.String())
	client.conn.Write(encodedPacket)
}
