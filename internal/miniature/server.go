package miniature

import (
	"bufio"
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
)

type Peer struct {
	IP            string
	Addr          *net.UDPAddr
	LastHeartbeat time.Time
	Cert          []byte
	PublicKey     *rsa.PublicKey
}

type Server struct {
	tunInterface   *utilities.Tun
	network        *net.IPNet
	socket         *net.UDPConn
	ipPool         []string
	Config         ServerConfig
	connectionPool map[string]*Peer
	waiter         sync.WaitGroup
}

type ServerConfig struct {
	CertificatesDirectory string
	Network               string
	ListeningPort         int
}

func (server *Server) Run(config ServerConfig) {
	server.Config = config
	ifce, err := utilities.NewInterface()
	if err != nil {
		log.Print("Failed to create interface")
		return
	}

	ip, network, err := net.ParseCIDR(config.Network)
	if err != nil {
		log.Print("Failed to create interface")
		return
	}

	err = ifce.Configure(ip, ip, "1400")
	if err != nil {
		log.Printf("Error: %s \n", err)
		return
	}

	// route client traffic through tun interface
	command := fmt.Sprintf("route add %s dev %s", network.String(), ifce.Ifce.Name())
	utilities.RunCommand("ip", command)

	gatewayIfce, _, err := utilities.GetDefaultGateway()

	command = fmt.Sprintf("-A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT", ifce.Ifce.Name(), gatewayIfce)
	utilities.RunCommand("iptables", command)

	command = fmt.Sprintf("-A FORWARD -i %s -o %s -j ACCEPT", gatewayIfce, ifce.Ifce.Name())
	utilities.RunCommand("iptables", command)

	command = fmt.Sprintf("-t nat -A POSTROUTING -o %s -j MASQUERADE", gatewayIfce)
	utilities.RunCommand("iptables", command)

	server.tunInterface = ifce
	server.network = network
	server.connectionPool = make(map[string]*Peer)

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

	server.waiter.Add(2)
	server.createIPPool()
	server.listenTLS()
	go server.listenAndServe()
	go server.readIfce()

	server.watchConnections()
	server.waiter.Wait()
}

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
	_, gatewayIP, err := utilities.GetDefaultGateway()
	if err != nil {
		return "", err
	}

	clientConfig := new(ClientConfig)
	clientConfig.ServerAddress = gatewayIP
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
		err = os.MkdirAll(server.Config.CertificatesDirectory, 700)
		if err != nil {
			return err
		}
	}
	cert := new(cryptography.Cert)
	cert.IsCA = true
	cert.Country = "Uganda"
	cert.Organization = "GenieLabs"
	cert.CommonName = "GenieLabs"
	cert.IPAddress = "172.20.0.4"

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
	defer conn.Close()
	p384 := ecdh.Generic(elliptic.P384())
	buffer := make([]byte, 512)
	for {
		_, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Connection to %s closed \n", conn.RemoteAddr().String())
			break
		}
		packet := new(utilities.Packet)
		utilities.Decode(packet, buffer)
		if packet.PacketHeader.Flag == utilities.HANDSHAKE {
			log.Println("Initiating Handshake")
			clientPublicKey := packet.PublicKey
			if err := p384.Check(clientPublicKey); err != nil {
				log.Println("Public Key is not on the curve")
				continue
			}

			serverPrivateKey, serverPublicKey, err := p384.GenerateKey(rand.Reader)
			if err != nil {
				log.Println(err)
				continue
			}

			secret := p384.ComputeSecret(serverPrivateKey, clientPublicKey)
			log.Println(secret)
			packetHeaderData := utilities.PacketHeader{Flag: utilities.HANDSHAKE_ACCEPTED}
			packetData := utilities.Packet{PacketHeader: packetHeaderData, PublicKey: serverPublicKey}
			clientIP := server.getAvailableIP()
			clientIPv4 := net.ParseIP(clientIP)
			ip := utilities.Addr{IpAddr: clientIPv4, Network: *server.network, Gateway: server.tunInterface.Ip}
			encodedIP, err := utilities.Encode(&ip)
			if err != nil {
				log.Printf("Error encoding IP address data \t Error : %s \n", err)
				continue
			}

			packetData.Payload = encodedIP
			encodedPacket, err := utilities.Encode(packetData)
			if err != nil {
				log.Printf("Error encoding packet \t Error : %s \n", err)
				continue
			}
			log.Printf("The number of available IP's was %v \n", len(server.ipPool))
			log.Printf("Assigning client an IP address of %s \n", clientIP)
			log.Printf("The number of available IP's is now %v \n", len(server.ipPool))
			conn.Write(encodedPacket)
		}
	}
}

func (server *Server) listenAndServe() {
	defer server.waiter.Done()

	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", server.Config.ListeningPort))
	if err != nil {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}

	lstnConn, err := net.ListenUDP("udp", lstnAddr)
	if nil != err {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}

	server.socket = lstnConn
	defer lstnConn.Close()
	inputBytes := make([]byte, 2048)
	packet := new(utilities.Packet)
	for {
		length, addr, err := lstnConn.ReadFromUDP(inputBytes)
		if err != nil || length == 0 {
			log.Println("Error: ", err)
			continue
		}

		log.Printf("Received %d bytes from %v \n", length, addr)

		err = utilities.Decode(packet, inputBytes[:length])
		if err != nil {
			log.Printf("An error occured while parsing packets recieved from client \t Error : %s \n", err)
			continue
		}

		packetHeader := packet.PacketHeader
		headerFlag := packetHeader.Flag

		switch headerFlag {
		case utilities.HEARTBEAT:
			server.handleHeartbeat(packet.Payload)
		case utilities.SESSION:
			server.handleConnection(packet.Payload)
		default:
			log.Println("Expected headers not found")
		}
	}
}

func (server *Server) handleConnection(packet []byte) {
	server.tunInterface.Ifce.Write(packet)
}

func (server *Server) registerClient(addr *net.UDPAddr, payload []byte) {
	peer := new(Peer)

	err := utilities.Decode(peer, payload)

	if err != nil {
		log.Printf("Error decoding peer data \t Error : %s \n", err)
		return
	}

	fmt.Printf("Registering client with IP address %s \n", peer.IP)
	peer.Addr = addr
	server.connectionPool[peer.IP] = peer

	packet := new(utilities.Packet)
	packet.PacketHeader = utilities.PacketHeader{Flag: utilities.SESSION_ACCEPTED}
	packet.Payload = make([]byte, 0)

	encodedPacket, err := utilities.Encode(packet)

	if err != nil {
		log.Printf("Error encoding peer packet \t Error : %s \n", err)
		return
	}

	log.Printf("Sending session accepted response to peer at %s \n", addr)
	writes, err := server.socket.WriteTo(encodedPacket, addr)

	if err != nil {
		log.Printf("Error writting bytes to socket, error : %s \n", err)
	}
	log.Printf("Written %v bytes to UDP socket \n", writes)
	log.Printf("Total number of connections : %v \n", len(server.connectionPool))
	log.Printf("IP  addesses remaining in pool : %v \n", len(server.ipPool))

}

func (server *Server) handleHeartbeat(packet []byte) {
	peer := new(Peer)
	err := utilities.Decode(peer, packet)
	if err != nil {
		log.Println("Error decoding peer data", err)
	}
	oldPeer := server.connectionPool[peer.IP]
	peer.LastHeartbeat = time.Now()
	peer.Addr = oldPeer.Addr
	server.connectionPool[peer.IP] = peer

	log.Println("Recieved heartbeat from peer at ", peer.IP)
}

func (server *Server) getAvailableIP() (ip string) {
	if len(server.ipPool) > 0 {
		addr := server.ipPool[0]
		server.ipPool = server.ipPool[1:len(server.ipPool)]
		return addr
	}
	return " "
}

func (server *Server) createIPPool() int {
	log.Printf("The CIDR of this network is %s \n", server.network.String())
	log.Printf("Generating IP address for %s network space \n", server.network)

	ip := server.tunInterface.Ip
	for ip := ip.Mask(server.network.Mask); server.network.Contains(ip); constructIP(ip) {
		// skip if ip is the same as the vitual interface's
		if server.tunInterface.Ip.String() != ip.String() {
			server.ipPool = append(server.ipPool, ip.String())
		} else {
			log.Printf("Skipping the interface id %s \n", ip)
		}
	}

	server.ipPool = server.ipPool[1 : len(server.ipPool)-1]
	log.Printf("Generated %v ip addresses \n", len(server.ipPool))
	return len(server.ipPool)
}

func constructIP(ip net.IP) {
	for octet := len(ip) - 1; octet >= 0; octet-- {
		ip[octet]++
		if ip[octet] > 0 {
			break
		}
	}
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
			packetHeader := utilities.PacketHeader{Flag: utilities.SESSION}
			sendPacket := utilities.Packet{PacketHeader: packetHeader, Payload: buffer[:length]}
			encodedPacket, err := utilities.Encode(sendPacket)
			if err != nil {
				log.Printf("An error occured while trying to encode this packet \t Error : %s \n", err)
				return
			}
			log.Printf("Version %d, Protocol  %d \n", header.Version, header.Protocol)
			peer := server.connectionPool[header.Dst.String()]
			log.Printf("Sending %d bytes to %s \n", header.Len, peer.Addr.String())
			server.socket.WriteToUDP(encodedPacket, peer.Addr)
		}
	}
}

func (server *Server) watchConnections() {
	utilities.RunCron("Cleaner", "0 0/5 * * * *", server.cleanupDeadConnections)
}

func (server *Server) cleanupDeadConnections() {
	for k, v := range server.connectionPool {
		currentTime := time.Now()
		timeDifference := currentTime.Sub(v.LastHeartbeat)
		elapsedMinutes := timeDifference.Minutes()
		if elapsedMinutes > 5.00 {
			log.Printf("Removing %s because the hearbeat has been quiet for %d minutes \n", k, elapsedMinutes)
			delete(server.connectionPool, k)
			log.Println(len(server.connectionPool))
		}
	}
}
