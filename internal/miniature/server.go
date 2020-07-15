package miniature

import (
	"bufio"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"gopkg.in/yaml.v3"

	"github.com/aead/ecdh"
	utilities "github.com/devgenie/miniature/internal/common"
	"github.com/devgenie/miniature/internal/cryptography"
	codec "github.com/devgenie/miniature/internal/cryptography"
)

// Peer represents a client connected to the VPN server
type Peer struct {
	//IP address of a client connected to the ser ver
	IP string
	// UDP object to communicate back to the peer
	Addr *net.UDPAddr
	// Time since the last hearbeat was got from the client
	LastHeartbeat time.Time
	// Server's private key for the peer
	ServerSecret []byte
}

// HandshakePacket represents a handshake packet
type HandshakePacket struct {
	// IP address to be assigned to the client
	ClientIP utilities.Addr
	// The public key of the server to be used for encryption
	ServerPublic crypto.PublicKey
}

// Server represents attributes of the VPN server
type Server struct {
	tunInterface   *utilities.Tun
	gatewayIfce    string
	network        *net.IPNet
	socket         *net.UDPConn
	ipPool         []string
	Config         ServerConfig
	connectionPool *Pool
	waiter         sync.WaitGroup
}

// ServerConfig holds VPN server configurations
// These configurations are read from a yaml file
type ServerConfig struct {
	CertificatesDirectory string
	Network               string
	ListeningPort         int
	PublicIP              string
	Metadata              struct {
		Country       string `yaml:"Country"`
		Organization  string `yaml:"Organization"`
		Unit          string `yaml:"Unit"`
		Locality      string `yaml:"Locality"`
		Province      string `yaml:"Province"`
		StreetAddress string `yaml:"StreetAddress"`
		PostalCode    string `yaml:"PostalCode"`
		CommonName    string `yaml:"CommonName"`
	}
}

// Run starts the VPN server by passing a configuration object
// The configuration object contains attributes needed to run the server
func (server *Server) Run(config ServerConfig) {
	server.Config = config
	ifce, err := utilities.NewInterface()
	if err != nil {
		log.Print("Failed to create interface")
		return
	}

	ip, network, err := net.ParseCIDR(config.Network)
	if err != nil {
		log.Println(err)
		log.Println("Failed to parse cidre")
		return
	}

	fmt.Println("TunIP", ip)
	err = ifce.Configure(ip, ip, "1400")
	if err != nil {
		log.Printf("Error: %s \n", err)
		return
	}

	// route client traffic through tun interface
	command := fmt.Sprintf("route add %s dev %s", network.String(), ifce.Ifce.Name())
	err = utilities.RunCommand("ip", command)
	if err != nil {
		return
	}

	gatewayIfce, _, err := utilities.GetDefaultGateway()
	if err != nil {
		return
	}

	command = fmt.Sprintf("-A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT", ifce.Ifce.Name(), gatewayIfce)
	err = utilities.RunCommand("iptables", command)
	if err != nil {
		return
	}

	command = fmt.Sprintf("-A FORWARD -i %s -o %s -j ACCEPT", gatewayIfce, ifce.Ifce.Name())
	err = utilities.RunCommand("iptables", command)
	if err != nil {
		return
	}

	command = fmt.Sprintf("-t nat -A POSTROUTING -o %s -j MASQUERADE", gatewayIfce)
	err = utilities.RunCommand("iptables", command)
	if err != nil {
		return
	}

	server.tunInterface = ifce
	server.network = network
	server.gatewayIfce = gatewayIfce

	log.Printf("Generating IP address for %s network space \n", server.network)
	connectionPool := InitNodePool(server.tunInterface.IP.String(), *server.network)
	server.connectionPool = connectionPool

	log.Printf("The CIDR of this network is %s \n", server.network)
	log.Printf("Tun interface assigned ip address %s \n", server.tunInterface.IP)
	log.Printf("Generated %v ip addresses \n", connectionPool.AvailableAddressesCount())

	certExists := true

	_, err = os.Stat(fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "ca.crt"))
	if err != nil {
		certExists = false
	}

	_, err = os.Stat(fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "privatekey.pem"))
	if err != nil {
		certExists = false
	}

	_, err = os.Stat(fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "publickey.pem"))
	if err != nil {
		certExists = false
	}

	if !certExists {
		log.Println("Could not find one or more certificate files, creating fresh ones")
		err = server.createCA()
		if err != nil {
			log.Println("Failed to create certificate files")
			return
		}
	} else {
		serverCertsExist := true
		_, err = os.Stat(fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "server.crt"))
		if err != nil {
			serverCertsExist = false
		}

		_, err = os.Stat(fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "server.pem"))
		if err != nil {
			serverCertsExist = false
		}

		if !serverCertsExist {
			log.Println("Could not find one or more server certificate files, creating fresh ones")
			err = server.generateServerCerts()
			if err != nil {
				log.Println("Failed to create server certificate files")
				return
			}
		}
	}

	server.waiter.Add(3)
	go server.listenTLS()
	go server.listenAndServe()
	go server.readIfce()

	server.waiter.Wait()
}

// CreateClientConfig creates a client configuration and parses it into yaml format
// Upon successfully creating the client configuration yaml file,
// a string representing the configuration and a nil error message is returned
func (server *Server) CreateClientConfig() (yamlConfiguration string, errorMessage error) {
	// get default gateway and add the public IP address to configuration
	certPath := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "ca.crt")
	privatekeyPath := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "privatekey.pem")
	privateKeyBytes, certBytes, err := server.generateCerts(certPath, privatekeyPath)
	if err != nil {
		return "", err
	}

	caCertBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	clientConfig := new(ClientConfig)
	clientConfig.ServerAddress = server.Config.PublicIP
	clientConfig.ListeningPort = server.Config.ListeningPort
	clientConfig.PrivateKey = string(privateKeyBytes)
	clientConfig.Certificate = string(certBytes)
	clientConfig.CACert = string(caCertBytes)

	configFile, err := yaml.Marshal(clientConfig)
	if err != nil {
		return "", err
	}
	return string(configFile), nil
}

func (server *Server) createCA() error {
	_, err := os.Stat(server.Config.CertificatesDirectory)
	if os.IsNotExist(err) {
		err = os.MkdirAll(server.Config.CertificatesDirectory, 0700)
		if err != nil {
			return err
		}
	}

	cert := new(cryptography.Cert)
	cert.IsCA = true
	cert.Country = server.Config.Metadata.Country
	cert.Organization = server.Config.Metadata.Organization
	cert.OrganizationalUnit = server.Config.Metadata.Unit
	cert.CommonName = server.Config.Metadata.CommonName
	cert.Locality = server.Config.Metadata.Locality
	cert.Province = server.Config.Metadata.Province
	cert.StreetAddress = server.Config.Metadata.StreetAddress
	cert.PostalCode = server.Config.Metadata.PostalCode
	cert.IPAddress = server.Config.PublicIP
	privateKey, publicKey, caCert, err := cert.GenerateCA()
	if err != nil {
		return err
	}

	// save server's certificate as a pem encoded crt file
	certificateFile, err := os.Create(fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "ca.crt"))
	if err != nil {
		log.Println("Failed to save certificate file")
		return err
	}

	certificatePem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert,
	}
	err = pem.Encode(certificateFile, certificatePem)
	if err != nil {
		return err
	}

	// save public key as pem encoded file
	publicKeyFile, err := os.Create(fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "publickey.pem"))
	if err != nil {
		log.Println("failed to save public key")
		return err
	}

	publicKeyANS1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Println(err)
		return err
	}
	publicKeyPem := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyANS1,
	}

	err = pem.Encode(publicKeyFile, publicKeyPem)
	if err != nil {
		log.Println("Failed to save private key")
		return err
	}

	// save private key as pem encoded file
	privateKeyFile, err := os.Create(fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "privatekey.pem"))
	if err != nil {
		log.Println("Failed to save private key")
		return err
	}

	privateKeyPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	err = pem.Encode(privateKeyFile, privateKeyPem)
	if err != nil {
		return err
	}

	log.Println("Successfully created certificate files")
	err = server.generateServerCerts()
	if err != nil {
		return err
	}
	return nil
}

func (server *Server) generateServerCerts() error {
	certPath := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "ca.crt")
	privatekeyPath := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "privatekey.pem")
	privateKeyBytes, certBytes, err := server.generateCerts(certPath, privatekeyPath)

	if err != nil {
		panic(err)
	}

	serverCertFile := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "server.crt")
	serverPrivatekeyPath := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "server.pem")
	err = ioutil.WriteFile(serverCertFile, certBytes, 0644)
	if err != nil {
		log.Println("Failed to write Certificate file")
		return err
	}

	err = ioutil.WriteFile(serverPrivatekeyPath, privateKeyBytes, 0644)
	if err != nil {
		log.Println("Failed to write private key")
		return err
	}

	return nil
}

func (server *Server) generateCerts(certPath string, privatekeyPath string) (privateKey []byte, cert []byte, err error) {
	serverCertificate, err := tls.LoadX509KeyPair(certPath, privatekeyPath)
	if err != nil {
		return nil, nil, err
	}

	ca, err := x509.ParseCertificate(serverCertificate.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	clientCertTemplate := *ca
	clientCertTemplate.IsCA = false

	privateKeyFile, err := os.Open(privatekeyPath)
	if err != nil {
		return nil, nil, err
	}
	defer privateKeyFile.Close()

	fileInfo, err := privateKeyFile.Stat()
	if err != nil {
		return nil, nil, err
	}
	filesize := fileInfo.Size()
	pemBytes := make([]byte, filesize)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pemBytes)
	if err != nil {
		return nil, nil, err
	}

	pemdata, _ := pem.Decode([]byte(pemBytes))

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(pemdata.Bytes)
	if err != nil {
		return nil, nil, err
	}

	clientCert := new(cryptography.Cert)
	clientPrivateKey, _, cert, err := clientCert.GenerateClientCertificate(&clientCertTemplate, ca, caPrivateKey)
	if err != nil {
		log.Println(err)
	}

	certpem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	certBytes := pem.EncodeToMemory(certpem)

	privateKeyPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientPrivateKey),
	}

	privateKeyBytes := pem.EncodeToMemory(privateKeyPem)
	return privateKeyBytes, certBytes, err
}

func (server *Server) listenTLS() {
	defer server.waiter.Done()
	caFile := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "ca.crt")
	crtFile := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "server.crt")
	privateKey := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "server.pem")

	certPem, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Println(err)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(certPem)
	if !ok {
		log.Println("Failed to parse certificate")
	}

	cert, err := tls.LoadX509KeyPair(crtFile, privateKey)
	if err != nil {
		log.Println(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	}

	listeningConn, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		log.Println(err)
		return
	}

	defer listeningConn.Close()
	gob.Register(ecdh.Point{})
	for {
		conn, err := listeningConn.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go server.handleTLS(conn)
	}
}

func (server *Server) handleTLS(conn net.Conn) {
	log.Println("Hadling tls")
	defer conn.Close()
	buffer := make([]byte, 512)
	for {
		_, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Connection to %s closed \n", conn.RemoteAddr().String())
			break
		}
		packet := new(utilities.Packet)
		err = utilities.Decode(packet, buffer)
		if err != nil {
			break
		}
		if packet.PacketHeader.Flag == utilities.HANDSHAKE {
			err = server.handleHandshake(conn, packet.Payload)
			if err != nil {
				break
			}
		}
	}
}

func (server *Server) handleHandshake(conn net.Conn, payload []byte) error {
	log.Println("Initiating Handshake")
	log.Println("Generating private key for this user session")

	gob.Register(rsa.PublicKey{})
	clientPublicKey := new(ecdh.Point)
	err := utilities.Decode(clientPublicKey, payload)
	if err != nil {
		log.Println("Failed to decode client public key")
		return err
	}

	serverKEX := ecdh.Generic(elliptic.P256())
	serverPrivateKey, serverPublicKey, err := serverKEX.GenerateKey(rand.Reader)
	if err != nil {
		log.Println(err)
		return err
	}
	peer := server.connectionPool.NewPeer()
	clientIPv4 := net.ParseIP(peer.IP)
	clientIP := utilities.Addr{IPAddr: clientIPv4, Network: *server.network, Gateway: server.tunInterface.IP}

	handshakePacket := new(HandshakePacket)
	handshakePacket.ClientIP = clientIP
	handshakePacket.ServerPublic = serverPublicKey
	packetHeaderData := utilities.PacketHeader{Flag: utilities.HANDSHAKE_ACCEPTED}

	handshakePacketBytes, err := utilities.Encode(handshakePacket)
	if err != nil {
		log.Println(err)
		return err
	}
	packetData := utilities.Packet{PacketHeader: packetHeaderData, Payload: handshakePacketBytes}
	encodedPacket, err := utilities.Encode(packetData)
	if err != nil {
		log.Printf("Error encoding packet \t Error : %s \n", err)
		return err
	}
	_, err = conn.Write(encodedPacket)
	if err != nil {
		return err
	}

	peer.ServerSecret = serverKEX.ComputeSecret(serverPrivateKey, clientPublicKey)
	log.Printf("Assigning client an IP address of %s \n", peer.IP)
	log.Printf("The number of available IP's is now %v \n", len(server.ipPool))
	return nil
}

func (server *Server) listenAndServe() {
	defer server.waiter.Done()

	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%v", server.Config.ListeningPort))
	if err != nil {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}

	lstnConn, err := net.ListenUDP("udp", lstnAddr)
	if err != nil {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}

	server.socket = lstnConn
	defer lstnConn.Close()
	inputBytes := make([]byte, 2048)
	packet := new(utilities.Packet)
	for {
		length, clientConn, err := lstnConn.ReadFromUDP(inputBytes)
		if err != nil || length == 0 {
			log.Println("Error: ", err)
			continue
		}

		decompressedData, err := Decompress(inputBytes[:length])
		if err != nil {
			log.Println(err)
			continue
		}
		err = utilities.Decode(packet, decompressedData)
		if err != nil {
			log.Printf("An error occured while parsing packets recieved from client \t Error : %s \n", err)
			continue
		}

		packetHeader := packet.PacketHeader
		headerFlag := packetHeader.Flag
		nonce := packetHeader.Nonce
		peer := server.connectionPool.GetPeer(packetHeader.Src)
		peer.Addr = clientConn
		decryptedPayload, err := codec.Decrypt(peer.ServerSecret, nonce, packet.Payload)
		if err != nil {
			log.Println("Failed to decrypt data")
			continue
		}

		switch headerFlag {
		case utilities.HEARTBEAT:
			server.handleHeartbeat(decryptedPayload)
		case utilities.SESSION:
			server.handleConnection(peer, decryptedPayload)
		default:
			log.Println("Expected headers not found")
		}
	}
}

func (server *Server) handleConnection(peer *Peer, packet []byte) {
	server.connectionPool.Update(peer.IP, *peer)
	_, err := server.tunInterface.Ifce.Write(packet)
	if err != nil {
		return
	}
}

// func (server *Server) registerClient(addr *net.UDPAddr, payload []byte) {
// 	peer := new(Peer)
// 	err := utilities.Decode(peer, payload)
// 	if err != nil {
// 		log.Printf("Error decoding peer data \t Error : %s \n", err)
// 		return
// 	}

// 	fmt.Printf("Registering client with IP address %s \n", peer.IP)
// 	server.connectionPool.NewPeer(addr)
// 	packet := new(utilities.Packet)
// 	packet.PacketHeader = utilities.PacketHeader{Flag: utilities.SESSION_ACCEPTED}
// 	packet.Payload = make([]byte, 0)

// 	encodedPacket, err := utilities.Encode(packet)

// 	if err != nil {
// 		log.Printf("Error encoding peer packet \t Error : %s \n", err)
// 		return
// 	}

// 	log.Printf("Sending session accepted response to peer at %s \n", addr)
// 	writes, err := server.socket.WriteTo(encodedPacket, addr)

// 	if err != nil {
// 		log.Printf("Error writting bytes to socket, error : %s \n", err)
// 	}
// 	log.Printf("Written %v bytes to UDP socket \n", writes)
// 	log.Printf("Total number of connections : %v \n", server.connectionPool.Size())
// 	log.Printf("IP  addesses remaining in pool : %v \n", len(server.ipPool))
// }

func (server *Server) handleHeartbeat(packet []byte) {
	peer := new(Peer)
	err := utilities.Decode(peer, packet)
	if err != nil {
		log.Println("Error decoding peer data", err)
	}
	oldPeer := server.connectionPool.GetPeer(peer.IP)
	peer.LastHeartbeat = time.Now()
	peer.Addr = oldPeer.Addr
	peer.ServerSecret = oldPeer.ServerSecret
	server.connectionPool.Update(oldPeer.IP, *peer)
	log.Println("Recieved heartbeat from peer at ", peer.IP)
}

func (server *Server) readIfce() {
	defer server.waiter.Done()
	log.Println("Handling outgoing connection")
	mtu := server.tunInterface.Mtu
	packetSize, err := strconv.Atoi(mtu)
	if err != nil {
		log.Printf("Error converting string to integer %s", err)
	}

	packetSize = packetSize - 400
	buffer := make([]byte, packetSize)
	for {
		length, err := server.tunInterface.Ifce.Read(buffer)
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
			peer := server.connectionPool.GetPeer(header.Dst.String())
			if peer != nil {
				packetHeader := utilities.PacketHeader{Flag: utilities.SESSION}
				sendPacket := utilities.Packet{PacketHeader: packetHeader, Payload: buffer[:length]}
				encodedPacket, err := utilities.Encode(sendPacket)
				if err != nil {
					log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
					return
				}
				log.Printf("Version %d, Protocol  %d \n", header.Version, header.Protocol)
				log.Printf("Sending %d bytes to %s \n", header.Len, peer.Addr.String())
				compressedPacket, err := Compress(encodedPacket)
				if err != nil {
					log.Println(err)
					return
				}
				fmt.Println(len(compressedPacket))
				_, err = server.socket.WriteTo(compressedPacket, peer.Addr)
				if err != nil {
					fmt.Println(err)
					return
				}
			}
			continue
		}
	}
}
