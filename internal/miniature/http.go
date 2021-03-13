package miniature

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type HTTPServer struct {
	server *Server
}

type stats struct {
	TimeElapsed             string
	GatewayInterfaceBytesIn int
	UDPTunnelBytesIn        int
	UDPTunnelBytesOut       int
	TotalBytesCompressed    int
	ConnectionsIn           int
	ConnectionsOut          int
	Peers                   int
	AvailableSlots          int
}

func (httpServer *HTTPServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		serverStats := new(stats)
		serverStats.ConnectionsIn = httpServer.server.metrics.ConnectionsIn
		serverStats.ConnectionsOut = httpServer.server.metrics.ConnectionsOut
		serverStats.TotalBytesCompressed = httpServer.server.metrics.TotalBytesCompressed
		serverStats.UDPTunnelBytesOut = httpServer.server.metrics.UDPTunnelBytesOut
		serverStats.UDPTunnelBytesIn = httpServer.server.metrics.UDPTunnelBytesIn
		serverStats.GatewayInterfaceBytesIn = httpServer.server.metrics.GatewayInterfaceBytesIn
		serverStats.Peers = httpServer.server.connectionPool.ConnectedPeersCount()
		serverStats.AvailableSlots = httpServer.server.connectionPool.AvailableAddressesCount()
		timeStarted := time.Unix(0, httpServer.server.metrics.TimeStarted)
		serverStats.TimeElapsed = time.Since(timeStarted).String()
		jsonResponse, _ := json.Marshal(serverStats)
		w.Write(jsonResponse)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func startHTTPServer(miniatureServer *Server) error {
	defer miniatureServer.waiter.Done()
	httpServer := new(HTTPServer)
	httpServer.server = miniatureServer
	http.HandleFunc("/stats", httpServer.handleStats)
	log.Println("Server started at 8080")
	err := http.ListenAndServe("127.0.0.1:8080", nil)
	return err
}
