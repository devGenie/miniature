package miniature

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

// HTTPServer ...
type HTTPServer struct {
	server *Server
}

type Stats struct {
	TimeElapsed             string `json:"TimeElapsed"`
	GatewayInterfaceBytesIn int    `json:"GatewayInterfaceBytesIn"`
	UDPTunnelBytesIn        int    `json:"UDPTunnelBytesIn"`
	UDPTunnelBytesOut       int    `json:"UDPTunnelBytesOut"`
	TotalBytesCompressed    int    `json:"TotalBytesCompressed"`
	ConnectionsIn           int    `json:"ConnectionsIn"`
	ConnectionsOut          int    `json:"ConnectionsOut"`
	Peers                   int    `json:"Peers"`
	AvailableSlots          int    `json:"AvailableSlots"`
}

func startHTTPServer(miniatureServer *Server) error {
	defer miniatureServer.waiter.Done()
	router := chi.NewRouter()
	router.Use(middleware.Recoverer)

	httpServer := new(HTTPServer)
	httpServer.server = miniatureServer

	router.Get("/stats", httpServer.handleStats)
	router.Post("/client", httpServer.createClientConfig)

	log.Println("Server started at 8080")
	err := http.ListenAndServe("127.0.0.1:8080", router)
	return err
}

func (httpServer *HTTPServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		serverStats := new(Stats)
		serverStats.ConnectionsIn = httpServer.server.metrics.ConnectionsIn
		serverStats.ConnectionsOut = httpServer.server.metrics.ConnectionsOut
		serverStats.TotalBytesCompressed = (httpServer.server.metrics.UDPTunnelBytesOut - httpServer.server.metrics.TotalBytesCompressed)
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

func (httpServer *HTTPServer) createClientConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		clientConfig, err := httpServer.server.CreateClientConfig()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Write([]byte(clientConfig))
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
