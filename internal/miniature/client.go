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
	ifce       *utilities.Tun
	serverConn *net.UDPAddr
	conn       *net.UDPConn
	waiter     sync.WaitGroup
	config     ClientConfig
	secret     []byte
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
	client.config = config
	if err := client.AuthenticateUser(); err != nil {
		log.Println(err)
		return err
	}

	if err := client.listen(client.config.ServerAddress,
		strconv.Itoa(client.config.ListeningPort)); err != nil {
		return err
	}

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
		return err
	}

	err = p256.Check(clientPublicKey)
	if err != nil {
		log.Println("Client's public key is not on curve")
	}
	packetHeader := utilities.PacketHeader{Flag: utilities.HANDSHAKE}
	publicKeyBytes, err := utilities.Encode(clientPublicKey)
	if err != nil {
		return err
	}

	packet := utilities.Packet{PacketHeader: packetHeader, Payload: publicKeyBytes}
	encodedData, err := utilities.Encode(&packet)
	if err != nil {
		return err
	}
	log.Println("Sending handshake to VPN server")
	_, err = conn.Write(encodedData)
	if err != nil {
		return err
	}

	buf := make([]byte, 512)
	for {
		_, err := conn.Read(buf)
		if err != nil {
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
				return err
			}

			err = p256.Check(handshakePacket.ServerPublic)
			if err != nil {
				return err
			}
			client.secret = p256.ComputeSecret(clientPrivatekey, handshakePacket.ServerPublic)

			ifce, err := utilities.NewInterface()
			if err != nil {
				return err
			}

			if err = ifce.Configure(handshakePacket.ClientIP.IPAddr,
				handshakePacket.ClientIP.Gateway,
				"1400"); err != nil {
				return err
			}

			log.Println("Client has been assigned ", handshakePacket.ClientIP.IPAddr)
			client.ifce = ifce
			client.ifce.Mtu = "1400"
			client.ifce.IP = handshakePacket.ClientIP.IPAddr

			log.Printf("Starting session, MTU of link is %s \n", client.ifce.Mtu)

			command := "route delete 0.0.0.0/0"
			if err = utilities.RunCommand("ip", command); err != nil {
				log.Printf("Error deleting route message: %s \n", err)
			}

			command = fmt.Sprintf("route add 0.0.0.0/0 via %s dev %s", client.ifce.IP.String(), client.ifce.Ifce.Name())
			if err = utilities.RunCommand("ip", command); err != nil {
				log.Printf("Error adding route to 0.0.0.0/0, message: %s \n", err)
			}
			client.StartHeartBeat()
			return nil
		}
	}
}

func (client *Client) listen(server, port string) error {
	lstnAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%v", 4221))
	conn, err := net.ListenUDP("udp4", lstnAddr)
	if err != nil {
		fmt.Println(err)
		log.Printf("Failed to connect to %s", server)
		return err
	}
	client.conn = conn
	return nil
}

func (client *Client) handleIncomingConnections() {
	defer client.waiter.Done()

	inputBytes := make([]byte, 2048)
	for {
		packet := new(utilities.Packet)
		length, _, err := client.conn.ReadFromUDP(inputBytes)
		if err != nil || length == 0 {
			log.Printf("Error : %s \n", err)
			continue
		}

		log.Printf("Recieved %d bytes \n", length)
		decompressedPacket, err := Decompress(inputBytes[:length])
		if err != nil {
			log.Println(err)
			continue
		}
		err = utilities.Decode(packet, decompressedPacket)
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

	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", client.config.ServerAddress, client.config.ListeningPort))
	if err != nil {
		log.Println("Failed to establish connection with the server")
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
			_, err := ipv4.ParseHeader(buffer[:length])
			if err != nil {
				log.Println(err)
				continue
			}

			encryptedData, nonce, err := codec.Encrypt(client.secret, buffer[:length])
			if err != nil {
				log.Println(err)
				continue
			}

			packetHeader := utilities.PacketHeader{Flag: utilities.SESSION, Nonce: nonce, Src: client.ifce.IP.String()}
			sendPacket := utilities.Packet{PacketHeader: packetHeader, Payload: encryptedData}
			encodedPacket, err := utilities.Encode(sendPacket)
			if err != nil {
				log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
				break
			}

			compressedPacket, err := Compress(encodedPacket)
			if err != nil {
				log.Println(err)
				continue
			}

			// log.Printf("Sending %d bytes to %s \n", len(compressedPacket), header.Dst)
			// log.Printf("Version %d, Protocol  %d \n", header.Version, header.Protocol)
			// log.Printf("UDP addr %v \n", client.conn.RemoteAddr())
			// log.Printf("Local addr %v \n", client.conn.LocalAddr())
			n, err := client.conn.WriteToUDP(compressedPacket, serverAddr)
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println(n)
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

	compressedPacket, err := Compress(encodedPacket)
	if err != nil {
		log.Println(err)
		return
	}

	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", client.config.ServerAddress, client.config.ListeningPort))

	log.Printf("Sending pulse to server at %s \n", serverAddr.String())

	_, err = client.conn.WriteToUDP(compressedPacket, serverAddr)
	if err != nil {
		return
	}
}
