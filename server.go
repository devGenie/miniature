package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

type Peer struct {
	IP            string
	Addr          *net.UDPAddr
	MacAddress    string
	LastHeartbeat time.Time
}

type Server struct {
	tunInterface   *Tun
	network        *net.IPNet
	socket         *net.UDPConn
	ipPool         []string
	connectionPool map[string]*Peer
}

func NewServer(address string) (*Server, error) {
	ifce, err := newInterface()
	if err != nil {
		log.Print("Failed to create interface")
		return nil, err
	}

	ip, network, err := net.ParseCIDR(address)
	if err != nil {
		log.Print("Failed to create interface")
		return nil, err
	}

	err = ifce.Configure(&ip, &ip, "1400")
	if err != nil {
		log.Printf("Error: %s \n", err)
		return nil, err
	}

	server := new(Server)
	server.tunInterface = ifce
	server.network = network
	server.connectionPool = make(map[string]*Peer)
	server.createIPPool()
	server.listenAndServe()
	return server, nil
}

func (server *Server) listenAndServe() {

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

		header, err := ipv4.ParseHeader(inputBytes[:length])
		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}
		fmt.Printf("Received %d bytes from %v: %+v\n", length, addr, header)

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
			server.handleHeartbeat(addr)
		case SESSION:
			server.handleConnection(packet, addr)
		default:
			fmt.Println("Expected headers not found")
		}
		// write to TUN interface
		//server.tunInterface.ifce.Write(inputBytes[:length])
	}
}

func (server *Server) handleConnection(packet *Packet, addr *net.UDPAddr) {
	fmt.Println("Handling connection")
	server.socket.WriteTo(packet.Payload, addr)
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

	ip := Addr{IpAddr: &clientIPv4, Network: server.network, Gateway: server.tunInterface.ip}

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

	fmt.Printf("Registering client with mac address %s \n", peer.IP)
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
	server.socket.WriteTo(encodedPacket, addr)
	fmt.Printf("Total number of connections : %v \n", len(server.connectionPool))
	fmt.Printf("IP  addesses remaining in pool : %v \n", len(server.ipPool))

}

func (server *Server) handleHeartbeat(add *net.UDPAddr) {
	fmt.Println("Handling heartbeat")
}

func (server *Server) routePackets() {

}

func (server *Server) getAvailableIP() (ip string) {
	if len(server.ipPool) > 0 {
		addr := server.ipPool[0]
		server.ipPool = server.ipPool[1:len(server.ipPool)]
		return addr
	} else {
		return " "
	}
}

func (server *Server) createIPPool() int {
	//ss := make([][]net.IP, 0)
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
