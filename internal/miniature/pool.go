package miniature

import (
	"log"
	"net"
	"sync"
	"time"
)

type Pool struct {
	Peers       map[string]*Peer
	Reserve     []string
	Mutex       *sync.Mutex
	peerTimeOut float64
}

// InitNodePool creates an empty nodepool and populates it with IP addresses
func InitNodePool(IPAddr net.IP, network net.IPNet) *Pool {
	ipaddr := &IPAddr

	nodePool := new(Pool)
	nodePool.Mutex = new(sync.Mutex)
	nodePool.Peers = make(map[string]*Peer)

	for addr := ipaddr.Mask(network.Mask); network.Contains(*ipaddr); constructIP(*ipaddr) {
		if ipaddr.String() != addr.String() {
			nodePool.Reserve = append(nodePool.Reserve, addr.String())
		} else {
			log.Printf("Skipping the interface id %s \n", addr.String())
		}
	}
	// pop out the first and last values from the generated IP pool
	// first value is the subnet address
	// last address is the broadcast address
	nodePool.Reserve = nodePool.Reserve[1 : len(nodePool.Reserve)-1]

	// start a timer to periodically remove dead peers and add them back to the reserve
	ticker := time.NewTicker(500 * time.Millisecond)
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				nodePool.cleanupExpired()
			}
		}
	}()
	return nodePool
}

func (pool *Pool) cleanupExpired() {
	now := time.Now()
	pool.Mutex.Lock()

	for k, v := range pool.Peers {
		timeSinceHeartBeat := now.Sub(v.LastHeartbeat)
		elapsedTime := timeSinceHeartBeat.Seconds()
		if elapsedTime > pool.peerTimeOut {
			delete(pool.Peers, k)
			pool.Reserve = append(pool.Reserve, k)
		}
	}
}

// GetPeer returns a peer corresponding to
func (pool *Pool) GetPeer(ipAddress string) *Peer {
	pool.Mutex.Lock()
	peer := pool.Peers[ipAddress]
	pool.Mutex.Unlock()
	return peer
}

// Update updates the peer
func (pool *Pool) Update(ipAddress string, peer Peer) {
	pool.Mutex.Lock()
	oldPeer := pool.Peers[ipAddress]
	oldPeer.LastHeartbeat = peer.LastHeartbeat
	pool.Mutex.Unlock()
}

// NewPeer assigns an IP address to a peer and records the UDP address to be used to contact
// the client
func (pool *Pool) NewPeer(UDPAddr *net.UDPAddr) *Peer {
	var peer *Peer
	pool.Mutex.Lock()
	if len(pool.Reserve) > 0 {
		peer = new(Peer)
		ipAddress := pool.Reserve[0]
		peer.IP = ipAddress
		peer.Addr = UDPAddr
		pool.Peers[ipAddress] = peer
	}
	pool.Mutex.Unlock()
	if peer == nil {
		return peer
	}
	return nil
}

func (pool *Pool) Size() int {
	return len(pool.Peers)
}

func constructIP(ip net.IP) {
	for octet := len(ip) - 1; octet >= 0; octet-- {
		ip[octet]++
		if ip[octet] > 0 {
			break
		}
	}
}
