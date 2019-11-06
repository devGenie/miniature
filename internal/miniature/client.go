package miniature

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/aead/ecdh"
	utilities "github.com/devgenie/miniature/internal/common"
	codec "github.com/devgenie/miniature/internal/cryptography"
	"golang.org/x/net/ipv4"
)

// Client represents a client connecting to the VPN server
type Client struct {
	ifce   *utilities.Tun
	conn   *net.UDPConn
	waiter sync.WaitGroup
	config ClientConfig
	secret []byte
}

// ClientConfig holds the client configuration loaded from the yml configuration file
type ClientConfig struct {
	// Address of the VPN server
	ServerAddress string
	// Port which the server is listening at
	ListeningPort int
	// Client's public key issued by the server
	Certificate string
	// Client's private key issued by the server
	PrivateKey string
	// The servers public key
	CACert string
}

// Run starts the vpn client passing the ClientConfig as a parameter
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

	client.waiter.Add(2)
	go client.handleIncomingConnections()
	go client.handleOutgoingConnections()
	client.waiter.Wait()
	return nil
}

// AuthenticateUser authenticates user with the vpn server
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

	p256 := ecdh.Generic(elliptic.P256())
	clientPrivatekey, clientPublicKey, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		log.Println(err)
		return err
	}

	err = p256.Check(clientPublicKey)
	if err != nil {
		log.Println("Client's public key is not on curve")
	}
	packetHeader := utilities.PacketHeader{Flag: utilities.HANDSHAKE}
	publicKeyBytes, err := utilities.Encode(clientPublicKey)
	if err != nil {
		log.Println("Failed to encode public key")
	}

	packet := utilities.Packet{PacketHeader: packetHeader, Payload: publicKeyBytes}
	encodedData, err := utilities.Encode(&packet)
	if err != nil {
		log.Println(err)
		return err
	}
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
		err = utilities.Decode(packetReply, buf)
		if err != nil {
			log.Println(err)
			return err
		}

		if packetReply.PacketHeader.Flag == utilities.HANDSHAKE_ACCEPTED {
			log.Println("Server Handshake accepted, configuring client interfaces")
			handshakePacket := new(HandshakePacket)
			err := utilities.Decode(handshakePacket, packetReply.Payload)
			if err != nil {
				log.Println(err)
				return err
			}

			err = p256.Check(handshakePacket.ServerPublic)
			if err != nil {
				log.Println(err)
				log.Println("Server's public key is not on the elliptic curve")
			}
			client.secret = p256.ComputeSecret(clientPrivatekey, handshakePacket.ServerPublic)
			log.Println(len(client.secret))

			ifce, err := utilities.NewInterface()
			if err != nil {
				log.Println("Error creating tun interface")
				return err
			}

			err = ifce.Configure(handshakePacket.ClientIP.IPAddr, handshakePacket.ClientIP.Gateway, "1400")
			if err != nil {
				log.Printf("Error: %s \n", err)
				return err
			}

			log.Println("Client has been assigned ", handshakePacket.ClientIP.IPAddr)
			client.ifce = ifce

			log.Printf("Starting session, MTU of link is %s \n", client.ifce.Mtu)

			command := "route delete 0.0.0.0/0"
			err = utilities.RunCommand("ip", command)
			if err != nil {
				log.Printf("Error deleting route message: %s \n", err)
			}

			command = fmt.Sprintf("route add 0.0.0.0/0 via %s dev %s", client.ifce.IP.String(), client.ifce.Ifce.Name())
			err = utilities.RunCommand("ip", command)
			if err != nil {
				log.Printf("Error adding route to 0.0.0.0/0, message: %s \n", err)
			}
			client.StartHeartBeat()
			return nil
		}
	}
}

func (client *Client) listen(server, port string) {
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

		log.Printf("Recieved %d bytes \n", length)
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
	_, err := client.ifce.Ifce.Write(packet)
	if err != nil {
		return
	}
}

func (client *Client) handleOutgoingConnections() {
	defer client.waiter.Done()
	packetSize, err := strconv.Atoi(client.ifce.Mtu)
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

			encryptedData, nonce, err := codec.Encrypt(client.secret, buffer[:length])
			if err != nil {
				log.Println(err)
				continue
			}

			packetHeader := utilities.PacketHeader{Flag: utilities.SESSION, Nonce: nonce}
			sendPacket := utilities.Packet{PacketHeader: packetHeader, Payload: encryptedData}
			encodedPacket, err := utilities.Encode(sendPacket)
			if err != nil {
				log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
				return
			}

			log.Printf("Sending %d bytes to %s \n", len(encodedPacket), header.Dst)
			log.Printf("Version %d, Protocol  %d \n", header.Version, header.Protocol)
			_, err = client.conn.Write(encodedPacket)
			if err != nil {
				return
			}
		}
	}
}

// StartHeartBeat creates a cron that sends th clients heartbeat to the server
func (client *Client) StartHeartBeat() {
	utilities.RunCron("Heartbeat", "0 0/1 * * * *", client.HeartBeat)
}

// HeartBeat sends the client's heartbeat to the server
func (client *Client) HeartBeat() {
	peer := new(Peer)
	peer.IP = client.ifce.IP.String()
	encodedPeer, err := utilities.Encode(&peer)
	if err != nil {
		log.Printf("An error occured while encording peer data \t Error : %s \n", err)
		return
	}

	encryptedData, nonce, err := codec.Encrypt(client.secret, encodedPeer)
	if err != nil {
		log.Println(err)
		return
	}

	packetHeader := utilities.PacketHeader{Flag: utilities.HEARTBEAT, Nonce: nonce, Src: client.ifce.IP.String()}
	sendPacket := utilities.Packet{PacketHeader: packetHeader, Payload: encryptedData}
	encodedPacket, err := utilities.Encode(sendPacket)
	if err != nil {
		log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
		return
	}

	serverAddress := client.conn.RemoteAddr()
	log.Printf("Sending pulse to server at %s \n", serverAddress.String())

	_, err = client.conn.Write(encodedPacket)
	if err != nil {
		return
	}
}
