package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sxueck/downloader/internal/client"
	"github.com/sxueck/downloader/internal/config"
)

func main() {
	configPath := flag.String("config", "client_config.yaml", "Path to config file")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	tunnel := client.NewTunnel(cfg.Server.Address, cfg.Server.AuthToken)

	if err := connectWithRetry(tunnel, cfg.Tunnel.ReconnectInterval); err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}

	username := ""
	password := ""
	if cfg.Socks5.Authentication {
		username = cfg.Socks5.Username
		password = cfg.Socks5.Password
	}

	socks5Server := client.NewSocks5Server(cfg.Socks5.Port, username, password, tunnel)
	if err := socks5Server.Start(); err != nil {
		log.Fatalf("Failed to start SOCKS5 server: %v", err)
	}

	go heartbeatLoop(tunnel, cfg.Tunnel.HeartbeatInterval)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	socks5Server.Stop()
	tunnel.Close()
}

func connectWithRetry(tunnel *client.Tunnel, retryInterval int) error {
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		if err := tunnel.Connect(); err != nil {
			log.Printf("Connection attempt %d failed: %v", i+1, err)
			if i < maxRetries-1 {
				time.Sleep(time.Duration(retryInterval) * time.Second)
				continue
			}
			return err
		}
		log.Println("Connected to server")
		return nil
	}
	return nil
}

func heartbeatLoop(tunnel *client.Tunnel, interval int) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
	}
}

