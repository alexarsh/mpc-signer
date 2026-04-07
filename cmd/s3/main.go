package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/alexarsh/mpc-signer/config"
	"github.com/alexarsh/mpc-signer/internal/api"
	"github.com/alexarsh/mpc-signer/internal/keystore"
	"github.com/alexarsh/mpc-signer/internal/transport"
)

func main() {
	configPath := flag.String("config", "config/s3.yaml", "path to config file")
	flag.Parse()

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	log.Printf("Starting MPC Node %s (WebSocket client)", cfg.Node.ID)

	// Initialize keystore
	store, err := keystore.NewStore(cfg.Keystore.Dir, cfg.Keystore.Passphrase)
	if err != nil {
		log.Fatalf("init keystore: %v", err)
	}

	// S3 is a WebSocket client — connects to S1 (hub)
	wsURL := fmt.Sprintf("ws://%s:%d/ws", cfg.Peer.Host, cfg.Peer.Port)

	// Retry connection to S1 (S1 might not be up yet)
	var ws *transport.Transport
	for i := 0; i < 10; i++ {
		ws, err = transport.NewClient(cfg.Node.ID, wsURL)
		if err == nil {
			break
		}
		log.Printf("[%s] waiting for S1 at %s... (%d/10)", cfg.Node.ID, wsURL, i+1)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("connect to S1: %v", err)
	}
	log.Printf("[%s] connected to S1 at %s", cfg.Node.ID, wsURL)

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
