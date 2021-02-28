package miniature

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"

	"github.com/aead/ecdh"
	utilities "github.com/devgenie/miniature/internal/common"
	codec "github.com/devgenie/miniature/internal/cryptography"
	"golang.org/x/net/ipv4"
)

// DefaultGateway represents the default gateway of the client.
type DefaultGateway struct {
	Interface string
	GatewayIP string
}

// Client represents a client connecting to the VPN server
type Client struct {
	ifce           *utilities.Tun
	serverAddr     *net.UDPAddr
	conn           *net.UDPConn
	waiter         sync.WaitGroup
	config         ClientConfig
	secret         []byte
	resolveFile    string
	defaultGateway DefaultGateway
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
		client.conn.Close()
		return err
	}
	defer client.conn.Close()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, os.Kill)
	go func() {
		select {
		case sig := <-c:
			log.Printf("Recieved %s signal, running some house keeping", sig)
			client.CleanUp()
			os.Exit(0)
		}
	}()

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

	buf := make([]byte, 1380)
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
			conn.Close()
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
				1500); err != nil {
				return err
			}

			log.Println("Client has been leased ", handshakePacket.ClientIP.IPAddr)
			client.ifce = ifce
			client.ifce.Mtu = 1500
			client.ifce.IP = handshakePacket.ClientIP.IPAddr
			gwIfce, gwIP, err := utilities.GetDefaultGateway()
			if err != nil {
				fmt.Println(err)
				return err
			}

			client.defaultGateway.GatewayIP = gwIP
			client.defaultGateway.Interface = gwIfce

			if runtime.GOOS == "linux" {
				err := SetUpLinuxClient(client.defaultGateway.Interface, client.defaultGateway.GatewayIP, client.ifce.Ifce.Name(), client.ifce.IP.String(), client.config.ServerAddress)
				if err != nil {
					return err
				}
			} else if runtime.GOOS == "darwin" {
				err := SetDarwinClient(client.defaultGateway.Interface, client.defaultGateway.GatewayIP, client.ifce.Ifce.Name(), client.ifce.IP.String(), client.config.ServerAddress)
				if err != nil {
					return err
				}
			}

			// command = fmt.Sprintf("route add %s via %s", client.config.ServerAddress, client.defaultGateway.Interface)
			// if err = utilities.RunCommand("ip", command); err != nil {
			// 	log.Printf("Error running %s, message: %s \n", command, err)
			// }

			// command = fmt.Sprintf("route add 0.0.0.0/0 via %s", client.ifce.IP)
			// if err = utilities.RunCommand("ip", command); err != nil {
			// 	log.Printf("Error running %s, message: %s \n", command, err)
			// }

			// for _, dnsServer := range handshakePacket.DNSResolvers {
			// 	command = fmt.Sprintf("route add %s via %s", dnsServer, client.ifce.IP)
			// 	if err = utilities.RunCommand("ip", command); err != nil {
			// 		log.Printf("Error running %s, message: %s \n", command, err)
			// 	}
			// }
			err = client.setUpDNS(handshakePacket.DNSResolvers)
			if err != nil {
				return err
			}

			client.StartHeartBeat()
			break
		}
	}
	return nil
}

func (client *Client) listen(server, port string) error {
	serverAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%s", server, port))
	if err != nil {
		log.Println("Failed to establish connection with the server")
		return err
	}
	client.serverAddr = serverAddr

	conn, err := net.DialUDP("udp4", nil, serverAddr)
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
	defer client.conn.Close()
	inputBytes := make([]byte, client.ifce.Mtu)
	for {
		packet := new(utilities.Packet)
		length, _, err := client.conn.ReadFromUDP(inputBytes)
		if err != nil || length == 0 {
			log.Printf("Error : %s \n", err)
			continue
		}
		fmt.Println("Reading from udp :", length)

		decompressedPacket, err := Decompress(inputBytes[:length])
		if err != nil {
			log.Println("Error decompressing", length)
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
		decryptedPayload, err := codec.Decrypt(client.secret, packet.Nonce, packet.Payload)
		if err != nil {
			log.Printf("Error decrypting data from the server \t Error : %s \n", err)
			continue
		}

		if headerFlag == utilities.SESSION {
			go client.writeToIfce(decryptedPayload)
		} else {
			log.Println("Expected headers not found")
		}
	}
}

func (client *Client) writeToIfce(packet []byte) {
	_, err := client.ifce.Ifce.Write(packet)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func (client *Client) handleOutgoingConnections() {
	defer client.waiter.Done()
	log.Println("Handling outgoing connection")

	buffer := make([]byte, 1300)
	for {
		length, err := client.ifce.Ifce.Read(buffer)
		if err != nil {
			log.Println("Error reading interface:", err)
			continue
		}

		go fmt.Println("Reading from interface:", length)

		if length > -4 {
			_, err := ipv4.ParseHeader(buffer[:length])
			if err != nil {
				log.Println("Error parsing header", err)
				continue
			}

			encryptedData, nonce, err := codec.Encrypt(client.secret, buffer[:length])
			if err != nil {
				log.Println("Error encrypting", err)
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
				log.Println("Error compressing:", err)
				continue
			}

			// log.Printf("Sending %d bytes to %s \n", len(compressedPacket), header.Dst)
			// log.Printf("Version %d, Protocol  %d \n", header.Version, header.Protocol)

			go func() {
				n, err := client.conn.Write(compressedPacket)
				if err != nil {
					fmt.Println("Failed to write to tunnel", err)
				}
				go fmt.Println("Writting to tunnel:", n)
			}()
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
		log.Println("Error compressing", err)
		return
	}

	log.Printf("Sending pulse to server at %s \n", client.serverAddr.String())

	_, err = client.conn.Write(compressedPacket)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func (client *Client) setUpDNS(resolvers []string) error {
	oldResolveFileContents, err := ioutil.ReadFile("/etc/resolv.conf")
	if err != nil {
		return err
	}
	client.resolveFile = string(oldResolveFileContents)
	content := "# Generated by miniature \n"
	for _, resolver := range resolvers {
		content += fmt.Sprintf("nameserver %s\n", resolver)
	}
	return ioutil.WriteFile("/etc/resolv.conf", []byte(content), 0644)
}

// ResetDNS resets the resolv.conf file to the one before the vpn client was started
func (client *Client) ResetDNS() error {
	err := ioutil.WriteFile("/etc/resolv.conf", []byte(client.resolveFile), 0644)
	if err != nil {
		log.Println("Failed to restore /etc/resolv.conf file, restore the file manually by copying the contents below and pasting them into /etc/resolve.conf file")
		fmt.Println(client.resolveFile)
	}
	return err
}

// CleanUp cleans up the client after a shutdown
func (client *Client) CleanUp() {
	client.ResetDNS()
}
