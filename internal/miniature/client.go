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
	"github.com/devgenie/miniature/internal/common"
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
	ifce              *utilities.Tun
	serverAddr        *net.UDPAddr
	conn              *net.UDPConn
	waiter            sync.WaitGroup
	config            ClientConfig
	secret            []byte
	resolveFile       string
	defaultGateway    DefaultGateway
	diconnectionCount int
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

	client.diconnectionCount = 0
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
		log.Println(err)
		return err
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

	publicKeyBytes, err := utilities.Encode(clientPublicKey)
	if err != nil {
		return err
	}

	packet := utilities.Packet{Flag: utilities.HANDSHAKE, Payload: publicKeyBytes}
	encodedData, err := utilities.Encode(&packet)
	if err != nil {
		return err
	}
	log.Println("Sending handshake to VPN server")
	_, err = conn.Write(encodedData)
	if err != nil {
		return err
	}

	for {
		buf := make([]byte, 1380)
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

		if packetReply.Flag == utilities.HANDSHAKE_ACCEPTED {
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
				err := SetDarwinClient(client.defaultGateway.Interface, client.defaultGateway.GatewayIP, client.ifce.Ifce.Name(), client.ifce.IP.String(), client.config.ServerAddress, handshakePacket.DNSResolvers[0])
				if err != nil {
					return err
				}
			}
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
	for {
		inputBytes := make([]byte, client.ifce.Mtu)
		if client.diconnectionCount < 3 {
			length, _, err := client.conn.ReadFromUDP(inputBytes)
			if err != nil || length == 0 {
				log.Printf("Error : %s \n", err)
				client.diconnectionCount++
				continue
			}

			decompressedPacket, err := Decompress(inputBytes[:length])
			if err != nil {
				log.Println("Error decompressing", length)
				log.Println(err)
				continue
			}

			flag := decompressedPacket[len(decompressedPacket)-1]
			decompressedPacket = decompressedPacket[:len(decompressedPacket)-1]
			decryptedPayload, err := codec.Decrypt(client.secret, decompressedPacket)
			if err != nil {
				log.Printf("Error decrypting data from the server \t Error : %s \n", err)
				continue
			}

			if flag == utilities.SESSION {
				go client.writeToIfce(decryptedPayload)
			} else {
				log.Println("Expected headers not found")
			}
		} else {
			if err := client.AuthenticateUser(); err != nil {
				log.Println(err)
				return
			}
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

	for {
		buffer := make([]byte, 1300)
		length, err := client.ifce.Ifce.Read(buffer)
		if err != nil {
			log.Println("Error reading interface:", err)
			continue
		}
		go func(data []byte, length int) {
			if length > -4 {
				_, err := ipv4.ParseHeader(data)
				if err != nil {
					log.Println("Error parsing header", err)
					return
				}

				encryptedData, err := codec.Encrypt(client.secret, buffer[:length])
				if err != nil {
					log.Println("Error encrypting", err)
					return
				}

				clintIP := client.ifce.IP[len(client.ifce.IP)-4:]
				encryptedData = append(encryptedData, clintIP...)
				encryptedData = append(encryptedData, utilities.SESSION)
				compressedPacket, err := Compress(encryptedData)
				if err != nil {
					log.Println("Error compressing:", err)
					return
				}
				// log.Printf("Sending %d bytes to %s \n", len(compressedPacket), header.Dst)
				// log.Printf("Version %d, Protocol  %d \n", header.Version, header.Protocol)

				_, err = client.conn.Write(compressedPacket)
				if err != nil {
					fmt.Println("Failed to write to tunnel", err)
				}
			}
		}(buffer[:length], length)
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

	encryptedData, err := codec.Encrypt(client.secret, encodedPeer)
	if err != nil {
		log.Println(err)
		return
	}

	clintIP := client.ifce.IP[len(client.ifce.IP)-4:]
	encryptedData = append(encryptedData, clintIP...)
	encryptedData = append(encryptedData, utilities.HEARTBEAT)
	compressedPacket, err := Compress(encryptedData)
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

	if runtime.GOOS == "darwin" {
		command := fmt.Sprintf("-f %s", "/etc/pf.conf")
		err := utilities.RunCommand("pfctl", command)
		if err != nil {
			log.Println(err)
		}

		routes := []common.Route{
			{Destination: "0.0.0.0/0", NextHop: client.defaultGateway.GatewayIP, GWInterface: client.defaultGateway.GatewayIP},
		}
		for _, route := range routes {
			common.DeleteRoute(route.Destination)
			err := common.AddRoute(route)
			if err != nil {
				log.Println(err)
			}
		}
	}
}
