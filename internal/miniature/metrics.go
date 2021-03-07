package miniature

import (
	"sync"
)

//Metrics handles server metrics
type Metrics struct {
	TimeStarted          int64
	TotalBytesRecieved   int
	TotalClientBytesRead int
	TotalBytesSent       int
	TotalBytesCompressed int
	ConnectionsIn        int
	ConnectionsOut       int
	mutex                *sync.Mutex
}

func initMetrics() *Metrics {
	metrics := new(Metrics)
	metrics.mutex = new(sync.Mutex)
	return metrics
}

// Update updates metrics
func (metrics *Metrics) Update(clientBytesRead int, bytesUncompressed int, bytesCompressed int, bytesRecieved int) {
	metrics.mutex.Lock()
	metrics.TotalBytesRecieved += bytesRecieved
	metrics.TotalBytesCompressed += bytesCompressed
	metrics.TotalBytesSent += bytesUncompressed
	metrics.TotalClientBytesRead += clientBytesRead

	if clientBytesRead > 0 {
		metrics.ConnectionsIn++
	} else {
		metrics.ConnectionsOut++
	}
	metrics.mutex.Unlock()
}
