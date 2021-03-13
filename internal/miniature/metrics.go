package miniature

import (
	"sync"
)

//Metrics handles server metrics
type Metrics struct {
	TimeStarted             int64
	GatewayInterfaceBytesIn int
	UDPTunnelBytesIn        int
	UDPTunnelBytesOut       int
	TotalBytesCompressed    int
	ConnectionsIn           int
	ConnectionsOut          int
	mutex                   *sync.Mutex
}

func initMetrics() *Metrics {
	metrics := new(Metrics)
	metrics.mutex = new(sync.Mutex)
	return metrics
}

// Update updates metrics
func (metrics *Metrics) Update(clientBytesRead int, bytesUncompressed int, bytesCompressed int, bytesRecieved int) {
	metrics.mutex.Lock()
	metrics.GatewayInterfaceBytesIn += bytesRecieved
	metrics.TotalBytesCompressed += (bytesUncompressed - bytesCompressed)
	metrics.UDPTunnelBytesOut += bytesCompressed
	metrics.UDPTunnelBytesIn += clientBytesRead
	if clientBytesRead > 0 {
		metrics.ConnectionsIn++
	} else {
		metrics.ConnectionsOut++
	}
	metrics.mutex.Unlock()
}
