package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/devgenie/miniature/cryptography"
	"golang.org/x/net/ipv4"
)

type Peer struct {
	IP            string
	Addr          *net.UDPAddr
	LastHeartbeat time.Time
	Cert          []byte
	PublicKey     *rsa.PublicKey
}

type Server struct {
	tunInterface   *Tun
	network        *net.IPNet
	socket         *net.UDPConn
	ipPool         []string
	connectionPool map[string]*Peer
	waiter         sync.WaitGroup
}

type ServerConfig struct {
	CertificatesDirectory string
	Network               string
}

func NewServer(address string) {
	ifce, err := newInterface()
	if err != nil {
		log.Print("Failed to create interface")
		return
	}

	ip, network, err := net.ParseCIDR(address)
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
	command := fmt.Sprintf("route add %s dev %s", network.String(), ifce.ifce.Name())
	RunCommand("ip", command)

	gatewayIfce, _, err := getDefaultGateway()

	command = fmt.Sprintf("-A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT", ifce.ifce.Name(), gatewayIfce)
	RunCommand("iptables", command)

	command = fmt.Sprintf("-A FORWARD -i %s -o %s -j ACCEPT", gatewayIfce, ifce.ifce.Name())
	RunCommand("iptables", command)

	command = fmt.Sprintf("-t nat -A POSTROUTING -o %s -j MASQUERADE", gatewayIfce)
	RunCommand("iptables", command)

	server := new(Server)
	server.tunInterface = ifce
	server.network = network
	server.connectionPool = make(map[string]*Peer)

	err = server.createCertificates()
	if err != nil {
		log.Println("Failed to create certificate files")
	}
	server.waiter.Add(2)
	server.createIPPool()
	go server.listenAndServe()
	go server.readIfce()

	server.watchConnections()
	server.waiter.Wait()
}

func (server *Server) createCertificates() error {
	cert := new(cryptography.Cert)
	cert.IsCA = true
	cert.Country = "Uganda"
	cert.Organization = "GenieLabs"
	cert.CommonName = "GenieLabs"

	privateKey, publicKey, caCert, err := cert.GenerateCA()
	if err != nil {
		return err
	}

	// save server's certificate as a pem encoded crt file
	certificateFile, err := os.Create("ca.crt")
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
	publicKeyFile, err := os.Create("publickey.pem")
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
	privateKeyFile, err := os.Create("privatekey.pem")
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

	return nil
}

func (server *Server) listenAndServe() {
	defer server.waiter.Done()
	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", 4321))
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
	packet := new(Packet)
	for {
		length, addr, err := lstnConn.ReadFromUDP(inputBytes)

		if err != nil || length == 0 {
			fmt.Println("Error: ", err)
			continue
		}

		fmt.Printf("Received %d bytes from %v \n", length, addr)

		err = decode(packet, inputBytes[:length])

		if err != nil {
			log.Printf("An error occured while parsing packets recieved from client \t Error : %s \n", err)
			continue
		}

		packetHeader := packet.PacketHeader
		headerFlag := packetHeader.Flag

		switch headerFlag {
		case HANDSHAKE:
			server.handleHandshake(addr)
		case CLIENT_CONFIGURATION:
			server.registerClient(addr, packet.Payload)
		case HEARTBEAT:
			server.handleHeartbeat(packet.Payload)
		case SESSION:
			server.handleConnection(packet.Payload)
		default:
			fmt.Println("Expected headers not found")
		}
		// write to TUN interface
		//server.tunInterface.ifce.Write(inputBytes[:length])
	}
}

func (server *Server) handleConnection(packet []byte) {
	server.tunInterface.ifce.Write(packet)
}

func (server *Server) handleHandshake(addr *net.UDPAddr) {
	// During handshakes the following should happen
	// 1 - Authenticates client [TODO]
	// 2 - Check for available IP addresses from address pool
	// 3 - Assign IP address to client, send acknowlegment client to proceed with connection
	fmt.Printf("Handshake recieved from potential client with address %s \n", addr.String())

	clientIP := server.getAvailableIP()
	clientIPv4 := net.ParseIP(clientIP)
	packet := new(Packet)
	packet.PacketHeader = PacketHeader{Flag: HANDSHAKE_ACCEPTED}

	ip := Addr{IpAddr: clientIPv4, Network: *server.network, Gateway: server.tunInterface.ip}

	encodedIP, err := encode(&ip)

	if err != nil {
		log.Printf("Error encoding IP address data \t Error : %s \n", err)
		return
	}

	packet.Payload = encodedIP

	encodedPacket, err := encode(packet)

	if err != nil {
		log.Printf("Error encoding packet \t Error : %s \n", err)
		return
	}
	fmt.Printf("The number of available IP's was %v \n", len(server.ipPool))
	fmt.Printf("Assigning client an IP address of %s \n", clientIP)
	fmt.Printf("The number of available IP's is now %v \n", len(server.ipPool))
	server.socket.WriteTo(encodedPacket, addr)
}

func (server *Server) registerClient(addr *net.UDPAddr, payload []byte) {
	peer := new(Peer)

	err := decode(peer, payload)

	if err != nil {
		log.Printf("Error decoding peer data \t Error : %s \n", err)
		return
	}

	fmt.Printf("Registering client with IP address %s \n", peer.IP)
	peer.Addr = addr
	server.connectionPool[peer.IP] = peer

	packet := new(Packet)
	packet.PacketHeader = PacketHeader{Flag: SESSION_ACCEPTED}
	packet.Payload = make([]byte, 0)

	encodedPacket, err := encode(packet)

	if err != nil {
		log.Printf("Error encoding peer packet \t Error : %s \n", err)
		return
	}

	fmt.Printf("Sending session accepted response to peer at %s \n", addr)
	writes, err := server.socket.WriteTo(encodedPacket, addr)

	if err != nil {
		log.Printf("Error writting bytes to socket, error : %s \n", err)
	}
	fmt.Printf("Written %v bytes to UDP socket \n", writes)
	fmt.Printf("Total number of connections : %v \n", len(server.connectionPool))
	fmt.Printf("IP  addesses remaining in pool : %v \n", len(server.ipPool))

}

func (server *Server) handleHeartbeat(packet []byte) {
	peer := new(Peer)
	err := decode(peer, packet)
	if err != nil {
		fmt.Println("Error decoding peer data", err)
	}
	oldPeer := server.connectionPool[peer.IP]
	peer.LastHeartbeat = time.Now()
	peer.Addr = oldPeer.Addr
	server.connectionPool[peer.IP] = peer

	fmt.Println("Recieved heartbeat from peer at ", peer.IP)
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
	fmt.Printf("The CIDR of this network is %s \n", server.network.String())
	fmt.Printf("Generating IP address for %s network space \n", server.network)

	ip := server.tunInterface.ip
	for ip := ip.Mask(server.network.Mask); server.network.Contains(ip); constructIP(ip) {
		// skip if ip is the same as the vitual interface's
		if server.tunInterface.ip.String() != ip.String() {
			server.ipPool = append(server.ipPool, ip.String())
		} else {
			fmt.Printf("Skipping the interface id %s \n", ip)
		}
	}

	server.ipPool = server.ipPool[1 : len(server.ipPool)-1]
	fmt.Printf("Generated %v ip addresses \n", len(server.ipPool))
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
	fmt.Println("Handling outgoing connection")
	mtu := server.tunInterface.mtu
	packetSize, err := strconv.Atoi(mtu)

	if err != nil {
		fmt.Printf("Error converting string to integer %s", err)
	}

	packetSize = packetSize - 400
	buffer := make([]byte, packetSize)
	for {
		length, err := server.tunInterface.ifce.Read(buffer)
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
			fmt.Printf("Version %d, Protocol  %d \n", header.Version, header.Protocol)
			peer := server.connectionPool[header.Dst.String()]
			fmt.Printf("Sending %d bytes to %s \n", header.Len, peer.Addr.String())

			server.socket.WriteToUDP(encodedPacket, peer.Addr)
		}
	}
}

func (server *Server) watchConnections() {
	RunCron("Cleaner", "0 0/5 * * * *", server.cleanupDeadConnections)
}

func (server *Server) cleanupDeadConnections() {
	for k, v := range server.connectionPool {
		currentTime := time.Now()
		timeDifference := currentTime.Sub(v.LastHeartbeat)
		elapsedMinutes := timeDifference.Minutes()
		if elapsedMinutes > 5.00 {
			fmt.Printf("Removing %s because the hearbeat has been quiet for %d minutes \n", k, elapsedMinutes)
			delete(server.connectionPool, k)
			fmt.Println(len(server.connectionPool))
		}
	}
}
