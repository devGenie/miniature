package miniature

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/rickb777/date/period"
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

type ClientResponse struct {
	Cert []byte
}

func startHTTPServer(miniatureServer *Server) error {
	defer miniatureServer.waiter.Done()
	router := chi.NewRouter()
	router.Use(middleware.Recoverer)

	httpServer := new(HTTPServer)
	httpServer.server = miniatureServer

	router.Get("/stats", httpServer.handleStats)
	router.Post("/client/auth", httpServer.createClientConfig)

	log.Println("Server started at 8080")
	err := http.ListenAndServe("0.0.0.0:8080", router)
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
		timeElapsed, _ := period.NewOf(time.Since(timeStarted))
		serverStats.TimeElapsed = timeElapsed.Format()
		jsonResponse, _ := json.Marshal(serverStats)
		w.Write(jsonResponse)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (httpServer *HTTPServer) createClientConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		decoder := json.NewDecoder(r.Body)
		user := new(User)
		err := decoder.Decode(user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		db := new(DatabaseObject)
		db.Init()
		_, err = db.GetUser(user.Username, user.Password)
		if err != nil {
			log.Println("Failed to fetch user", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		clientConfig, err := httpServer.server.CreateClientConfig()
		if err != nil {
			log.Println("Failed to create client config", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			clientResponse := new(ClientResponse)
			clientResponse.Cert = []byte(clientConfig)
			jsonResponse, _ := json.Marshal(clientResponse)
			w.Write(jsonResponse)
		}
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
