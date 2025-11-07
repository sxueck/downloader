package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ClientConfig struct {
	Server ServerInfo `yaml:"server"`
	Socks5 Socks5Info `yaml:"socks5"`
	Tunnel TunnelInfo `yaml:"tunnel"`
}

type ServerConfig struct {
	Server ServerListenInfo `yaml:"server"`
	Limits LimitsInfo       `yaml:"limits"`
}

type ServerInfo struct {
	Address   string `yaml:"address"`
	AuthToken string `yaml:"auth_token"`
}

type Socks5Info struct {
	Port           int    `yaml:"port"`
	Authentication bool   `yaml:"authentication"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
}

type TunnelInfo struct {
	HeartbeatInterval int `yaml:"heartbeat_interval"`
	ReconnectInterval int `yaml:"reconnect_interval"`
}

type ServerListenInfo struct {
	Listen    string   `yaml:"listen"`
	AuthToken string   `yaml:"auth_token"`
	TLSCert   string   `yaml:"tls_cert"`
	TLSKey    string   `yaml:"tls_key"`
	Whitelist []string `yaml:"whitelist"`
}

type LimitsInfo struct {
	MaxConnections int `yaml:"max_connections"`
	IdleTimeout    int `yaml:"idle_timeout"`
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Socks5.Port == 0 {
		cfg.Socks5.Port = 1080
	}
	if cfg.Tunnel.HeartbeatInterval == 0 {
		cfg.Tunnel.HeartbeatInterval = 30
	}
	if cfg.Tunnel.ReconnectInterval == 0 {
		cfg.Tunnel.ReconnectInterval = 5
	}

	return &cfg, nil
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	if cfg.Limits.MaxConnections == 0 {
		cfg.Limits.MaxConnections = 1000
	}
	if cfg.Limits.IdleTimeout == 0 {
		cfg.Limits.IdleTimeout = 300
	}

	return &cfg, nil
}
