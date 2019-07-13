package miniature

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/aead/ecdh"
	utilities "github.com/devgenie/miniature/internal/common"
	"golang.org/x/net/ipv4"
)

type Client struct {
	ifce        *utilities.Tun
	conn        *net.UDPConn
	waiter      sync.WaitGroup
	sessionChan chan string
	config      ClientConfig
	secret      []byte
}

type ClientConfig struct {
	ServerAddress string
	ListeningPort int
	Certificate   string
	PrivateKey    string
	CACert        string
}

func (client *Client) Run(config ClientConfig) error {
	_, err := utilities.NewInterface()
	if err != nil {
		log.Printf("Failed to create interface")
	}
	client.config = config
	err = client.AuthenticateUser()
	if err != nil {
		log.Println(err)
		return err
	}

	client.listen(client.config.ServerAddress, strconv.Itoa(client.config.ListeningPort))
	defer client.conn.Close()
	client.sessionChan = make(chan string)
	client.waiter.Add(2)
	go client.handleIncomingConnections()
	go client.handleOutgoingConnections()

	client.waiter.Wait()
	return nil
}

func (client *Client) AuthenticateUser() error {
	caCert := []byte(client.config.CACert)
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(caCert)
	if !ok {
		log.Println("Failed to Parse certificate")
	}

	cert, err := tls.X509KeyPair([]byte(client.config.Certificate), []byte(client.config.PrivateKey))
	if err != nil {
		panic(err)
	}
	conf := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{cert},
	}

	serverAddress := fmt.Sprintf("%s:%d", client.config.ServerAddress, 443)
	conn, err := tls.Dial("tcp", serverAddress, conf)
	if err != nil {
		return err
	}
	defer conn.Close()

	p384 := ecdh.Generic(elliptic.P384())
	clientPrivatekey, clientPublic, err := p384.GenerateKey(rand.Reader)
	if err != nil {
		log.Println("Failed to generate client's public/private key pair")
		return err
	}

	packetHeader := utilities.PacketHeader{Flag: utilities.HANDSHAKE}
	gob.Register(ecdh.Point{})
	packet := utilities.Packet{PacketHeader: packetHeader, PublicKey: clientPublic}
	encodedData, err := utilities.Encode(&packet)
	log.Println("Sending handshake to VPN server")
	n, err := conn.Write(encodedData)
	if err != nil {
		log.Println(n, err)
		return err
	}

	buf := make([]byte, 512)
	for {
		n, err = conn.Read(buf)
		if err != nil {
			log.Println(n, err)
			return err
		}
		packetReply := new(utilities.Packet)
		utilities.Decode(packetReply, buf)

		if packetReply.PacketHeader.Flag == utilities.HANDSHAKE_ACCEPTED {
			log.Println("Server Handshake accepted, configuring client interfaces")
			ipaddr := new(utilities.Addr)
			err := utilities.Decode(ipaddr, packetReply.Payload)
			if err != nil {
				log.Println(err)
				return err
			}

			secret := p384.ComputeSecret(clientPrivatekey, packetReply.PublicKey)
			client.secret = secret

			ifce, err := utilities.NewInterface()
			if err != nil {
				log.Println("Error creating tun interface")
				return err
			}

			err = ifce.Configure(ipaddr.IpAddr, ipaddr.Gateway, "1400")
			if err != nil {
				log.Printf("Error: %s \n", err)
				return err
			}

			log.Println("Client has been assigned ", ipaddr.IpAddr)
			client.ifce = ifce

			log.Printf("Starting session, MTU of link is %s \n", client.ifce.Mtu)

			command := "route delete 0.0.0.0/0"
			err = utilities.RunCommand("ip", command)
			if err != nil {
				log.Printf("Error deleting route message: %s \n", err)
			}

			command = fmt.Sprintf("route add 0.0.0.0/0 via %s dev %s", client.ifce.Ip.String(), client.ifce.Ifce.Name())
			err = utilities.RunCommand("ip", command)
			if err != nil {
				log.Printf("Error adding route to 0.0.0.0/0, message: %s \n", err)
			}

			client.sessionChan <- client.ifce.Mtu
			client.StartHeartBeat()
			break
		}
	}
	return nil
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

func (client *Client) handleIncomingConnections() {
	defer client.waiter.Done()

	inputBytes := make([]byte, 2048)

	for {
		packet := new(utilities.Packet)
		length, err := client.conn.Read(inputBytes)
		if err != nil || length == 0 {
			log.Printf("Error : %s \n", err)
			continue
		}

		log.Printf("Recieved %s bytes \n", length)
		err = utilities.Decode(packet, inputBytes)
		if err != nil {
			log.Printf("Error decoding data from the server \t Error : %s \n", err)
			continue
		}

		packetHeader := packet.PacketHeader
		headerFlag := packetHeader.Flag

		if headerFlag == utilities.SESSION {
			client.writeToIfce(packet.Payload)
		} else {
			log.Println("Expected headers not found")
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
	log.Println("Handling outgoing connection")
	if err != nil {
		log.Printf("Error converting string to integer %s", err)
	}

	packetSize = packetSize - 400
	buffer := make([]byte, packetSize)
	for {
		length, err := client.ifce.Ifce.Read(buffer)
		if err != nil {
			log.Println(err)
			continue
		}

		if length > -4 {
			header, err := ipv4.ParseHeader(buffer[:length])
			if err != nil {
				log.Println(err)
				continue
			}

			packetHeader := utilities.PacketHeader{Flag: utilities.SESSION}
			sendPacket := utilities.Packet{PacketHeader: packetHeader, Payload: buffer[:length]}
			encodedPacket, err := utilities.Encode(sendPacket)
			if err != nil {
				log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
				return
			}

			log.Printf("Sending %d bytes to %s \n", len(encodedPacket), header.Dst)
			log.Printf("Version %d, Protocol  %d \n", header.Version, header.Protocol)

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
	log.Printf("Sending pulse to server at %s \n", serverAddress.String())
	client.conn.Write(encodedPacket)
}
