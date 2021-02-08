package miniature

import (
	"log"
	"net"
	"sync"
	"time"
)

// Pool is a pool of IP addresses
type Pool struct {
	Peers          map[string]*Peer
	Reserve        []string
	NetworkAddress string
	Mutex          *sync.Mutex
	peerTimeOut    float64
}

// InitNodePool creates an empty nodepool and populates it with IP addresses
func InitNodePool(IPAddr string, network net.IPNet) *Pool {
	ipaddr := net.ParseIP(IPAddr)
	nodePool := new(Pool)
	nodePool.Mutex = new(sync.Mutex)
	nodePool.Peers = make(map[string]*Peer)
	nodePool.peerTimeOut = float64(300)
	log.Println(nodePool.peerTimeOut)

	for addr := ipaddr.Mask(network.Mask); network.Contains(ipaddr); constructIP(ipaddr) {
		if !ipaddr.Equal(addr) {
			nodePool.Reserve = append(nodePool.Reserve, ipaddr.String())
		} else {
			log.Printf("Skipping the interface id %s \n", addr.String())
		}
	}
	// pop out the first and last values from the generated IP pool
	// first value is the subnet address
	// last address is the broadcast address
	nodePool.NetworkAddress = nodePool.Reserve[0]
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
	pool.Mutex.Lock()

	for k, v := range pool.Peers {
		timeSinceHeartBeat := time.Since(v.LastHeartbeat)
		elapsedTime := timeSinceHeartBeat.Seconds()
		if elapsedTime > pool.peerTimeOut {
			log.Printf("%s has been quiet for %g. Removing after %g timeout \n", k, elapsedTime, pool.peerTimeOut)
			delete(pool.Peers, k)
			pool.Reserve = append(pool.Reserve, k)
		}
	}
	pool.Mutex.Unlock()
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
func (pool *Pool) NewPeer() *Peer {
	var peer *Peer
	peer = nil
	pool.Mutex.Lock()
	if len(pool.Reserve) > 0 {
		peer = new(Peer)
		ipAddress := pool.Reserve[0]
		peer.IP = ipAddress
		peer.LastHeartbeat = time.Now()
		pool.Peers[ipAddress] = peer
		pool.Reserve = append(pool.Reserve[:0], pool.Reserve[1:]...)
	}
	pool.Mutex.Unlock()
	return peer
}

// ConnectedPeersCount is the number of peers connected to the server
func (pool *Pool) ConnectedPeersCount() int {
	return len(pool.Peers)
}

// AvailableAddressesCount is the number of available ip addresses to be leased to peers
func (pool *Pool) AvailableAddressesCount() int {
	return len(pool.Reserve)
}

func constructIP(ip net.IP) {
	for octet := len(ip) - 1; octet >= 0; octet-- {
		ip[octet]++
		if ip[octet] > 0 {
			break
		}
	}
}
