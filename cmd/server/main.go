package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sxueck/downloader/internal/config"
	"github.com/sxueck/downloader/internal/server"
)

func main() {
	configPath := flag.String("config", "server_config.yaml", "Path to config file")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	srv := server.NewServer(
		cfg.Server.Listen,
		cfg.Server.AuthToken,
		cfg.Server.TLSCert,
		cfg.Server.TLSKey,
		cfg.Limits.MaxConnections,
		cfg.Limits.IdleTimeout,
		cfg.Server.Whitelist,
	)

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	srv.Stop()
}
