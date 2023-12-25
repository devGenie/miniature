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
	"log"
	"net"
	"os"
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
	DNSResolvers []string
}

// Server represents attributes of the VPN server
type Server struct {
	tunInterface   *utilities.Tun
	gatewayIfce    string
	network        *net.IPNet
	socket         *net.UDPConn
	Config         ServerConfig
	connectionPool *Pool
	waiter         sync.WaitGroup
	metrics        *Metrics
}

// ServerConfig holds VPN server configurations
// These configurations are read from a yaml file
type ServerConfig struct {
	CertificatesDirectory string
	Network               string
	ListeningPort         int
	PublicIP              string
	DNSResolvers          []string
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
	fmt.Println(config.PublicIP)
	fmt.Println(config)
	server.Config = config
	ifce, err := utilities.NewInterface()
	if err != nil {
		log.Print("Failed to create interface")
		return
	}

	_, network, err := net.ParseCIDR(config.Network)
	if err != nil {
		log.Println(err)
		log.Println("Failed to parse cidre")
		return
	}

	log.Printf("Generating IP address for %s network space \n", network)
	server.connectionPool = InitNodePool(network.IP.String(), *network)
	log.Printf("Generated %v ip addresses \n", server.connectionPool.AvailableAddressesCount())

	ip := net.ParseIP(server.connectionPool.NetworkAddress)
	fmt.Println("TunIP", server.connectionPool.NetworkAddress)
	err = ifce.Configure(ip, ip, 1300)
	if err != nil {
		log.Printf("Error: %s \n", err)
		return
	}

	// route client traffic through tun interface
	command := fmt.Sprintf("route add %s dev %s", network.String(), ifce.Ifce.Name())
	err = utilities.RunCommand("ip", command)
	if err != nil {
		fmt.Println(err)
		return
	}

	gatewayIfce, _, err := utilities.GetDefaultGateway()
	if err != nil {
		fmt.Println("Failed to get default interface", gatewayIfce)
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

	command = fmt.Sprintf("-t filter -I OUTPUT -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", gatewayIfce)
	err = utilities.RunCommand("iptables", command)
	if err != nil {
		return
	}

	command = fmt.Sprintf("-t filter -I FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", gatewayIfce)
	err = utilities.RunCommand("iptables", command)
	if err != nil {
		return
	}

	server.tunInterface = ifce
	server.network = network
	server.gatewayIfce = gatewayIfce

	log.Printf("The CIDR of this network is %s \n", server.network)
	log.Printf("Tun interface assigned ip address %s \n", server.tunInterface.IP)

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
				fmt.Println(err)
				fmt.Println(server.gatewayIfce)
				fmt.Println(server)
				log.Println("Failed to create server certificate files")
				return
			}
		}
	}

	lstnAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%v", server.Config.ListeningPort))
	if err != nil {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}

	lstnConn, err := net.ListenUDP("udp4", lstnAddr)
	if err != nil {
		log.Fatalln("Unable to listen on UDP socket111:", err)
	}

	server.socket = lstnConn
	defer lstnConn.Close()

	server.metrics = initMetrics()
	server.metrics.TimeStarted = time.Now().UnixNano()

	server.waiter.Add(5)
	go server.listenTLS()
	go server.listenAndServe()
	go server.readIfce()
	go startHTTPServer(server)

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

	caCertBytes, err := os.ReadFile(certPath)
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
		return err
	}

	serverCertFile := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "server.crt")
	serverPrivatekeyPath := fmt.Sprintf("%s/%s", server.Config.CertificatesDirectory, "server.pem")
	err = os.WriteFile(serverCertFile, certBytes, 0644)
	if err != nil {
		log.Println("Failed to write Certificate file")
		return err
	}

	err = os.WriteFile(serverPrivatekeyPath, privateKeyBytes, 0644)
	if err != nil {
		log.Println("Failed to write private key")
		return err
	}

	return nil
}

func (server *Server) generateCerts(certPath string, privatekeyPath string) (privateKey []byte, cert []byte, err error) {
	serverCertificate, err := tls.LoadX509KeyPair(certPath, privatekeyPath)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	ca, err := x509.ParseCertificate(serverCertificate.Certificate[0])
	if err != nil {
		fmt.Println(err)
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

	certPem, err := os.ReadFile(caFile)
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
	log.Println("Handling tls")
	defer conn.Close()
	buffer := make([]byte, 512)
	for {
		_, err := conn.Read(buffer)
		if err != nil {
			log.Println(err)
			break
		}
		packet := new(utilities.Packet)
		err = utilities.Decode(packet, buffer)
		if err != nil {
			log.Println(err)
			break
		}
		if packet.Flag == utilities.HANDSHAKE {
			err = server.handleHandshake(conn, packet.Payload)
			if err != nil {
				fmt.Println(err)
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
	handshakePacket.DNSResolvers = server.Config.DNSResolvers

	handshakePacketBytes, err := utilities.Encode(handshakePacket)
	if err != nil {
		return err
	}
	packetData := utilities.Packet{Flag: utilities.HANDSHAKE_ACCEPTED, Payload: handshakePacketBytes}
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
	return nil
}

func (server *Server) listenAndServe() {
	defer server.waiter.Done()

	for {
		inputBytes := make([]byte, 1483)
		length, clientConn, err := server.socket.ReadFromUDP(inputBytes)
		fmt.Println("Read from", clientConn.IP)
		go server.metrics.Update(length, 0, 0, 0)
		if err != nil || length == 0 {
			log.Println("Error: ", err)
			continue
		}
		go func(data []byte) {
			decompressedData, err := Decompress(data)
			if err != nil {
				log.Println("Failed to decompress data: ", err)
				return
			}

			headerData := decompressedData[len(decompressedData)-5:]
			decompressedData = decompressedData[:len(decompressedData)-5]
			srcIP := net.IP(headerData[:4])
			headerFlag := headerData[4]
			peer := server.connectionPool.GetPeer(srcIP.String())
			if peer == nil {
				fmt.Println("Failed to get peer")
				return
			}

			peer.Addr = clientConn
			decryptedPayload, err := codec.Decrypt(peer.ServerSecret, decompressedData)
			if err != nil {
				log.Println("Failed to decrypt data")
				return
			}

			switch headerFlag {
			case utilities.HEARTBEAT:
				server.handleHeartbeat(decryptedPayload)
			case utilities.SESSION:
				go server.handleConnection(peer, decryptedPayload)
			default:
				log.Println("Expected headers not found")
			}
		}(inputBytes[:length])
	}
}

func (server *Server) handleConnection(peer *Peer, packet []byte) {
	fmt.Println("Handling session")
	server.connectionPool.Update(peer.IP, *peer)
	_, err := server.tunInterface.Ifce.Write(packet)
	if err != nil {
		fmt.Println(err)
		return
	}
}

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
}

func (server *Server) readIfce() {
	defer server.waiter.Done()
	log.Println("Handling outgoing connection")
	for {
		fmt.Println("Received data")
		buffer := make([]byte, server.tunInterface.Mtu)
		length, err := server.tunInterface.Ifce.Read(buffer)
		if err != nil {
			log.Println(err)
			continue
		}

		go func(data []byte, length int) {
			if length > -4 {
				header, err := ipv4.ParseHeader(data)
				if err != nil {
					log.Println("Error parsing header", err)
					return
				}
				peer := server.connectionPool.GetPeer(header.Dst.String())
				if peer != nil {
					encryptedData, err := codec.Encrypt(peer.ServerSecret, buffer[:length])
					sendPacket := append(encryptedData, utilities.SESSION)
					if err != nil {
						log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
						return
					}

					compressedPacket, err := Compress(sendPacket)
					if err != nil {
						log.Println(err)
						return
					}

					fmt.Println("Writting to: ", peer.Addr)
					_, err = server.socket.WriteTo(compressedPacket, peer.Addr)
					if err != nil {
						fmt.Println(err)
						return
					}
					go server.metrics.Update(0, len(sendPacket), len(compressedPacket), length)
				}
				return
			}
		}(buffer[:length], length)
	}
}
