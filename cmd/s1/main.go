package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/alexarsh/mpc-signer/config"
	"github.com/alexarsh/mpc-signer/internal/api"
	"github.com/alexarsh/mpc-signer/internal/keystore"
	"github.com/alexarsh/mpc-signer/internal/transport"
)

func main() {
	configPath := flag.String("config", "config/s1.yaml", "path to config file")
	flag.Parse()

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	log.Printf("Starting MPC Node %s (WebSocket server)", cfg.Node.ID)

	// Initialize keystore
	store, err := keystore.NewStore(cfg.Keystore.Dir, cfg.Keystore.Passphrase)
	if err != nil {
		log.Fatalf("init keystore: %v", err)
	}

	// S1 is the WebSocket server — peers connect to it
	ws := transport.NewServer(cfg.Node.ID)

	// Start WebSocket server on a separate port
	wsPort := cfg.Peer.Port
	wsMux := http.NewServeMux()
	wsMux.HandleFunc("/ws", ws.HandleConnection)
	go func() {
		wsAddr := fmt.Sprintf("0.0.0.0:%d", wsPort)
		log.Printf("[%s] WebSocket server listening on %s", cfg.Node.ID, wsAddr)
		if err := http.ListenAndServe(wsAddr, wsMux); err != nil {
			log.Fatalf("WebSocket server: %v", err)
		}
	}()

	// Set up REST API
	r := gin.Default()
	server := api.NewServer(cfg.Node.ID, store, ws)
	server.RegisterRoutes(r)
	server.StartProtocolListener()

	// Start REST API
	apiAddr := fmt.Sprintf("%s:%d", cfg.API.Host, cfg.API.Port)
	log.Printf("[%s] REST API listening on %s", cfg.Node.ID, apiAddr)
	if err := r.Run(apiAddr); err != nil {
		log.Fatalf("REST API server: %v", err)
	}
}
