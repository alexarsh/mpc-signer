package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Node      NodeConfig      `yaml:"node"`
	Peer      PeerConfig      `yaml:"peer"`
	API       APIConfig       `yaml:"api"`
	Keystore  KeystoreConfig  `yaml:"keystore"`
	Tron      TronConfig      `yaml:"tron"`
}

type NodeConfig struct {
	ID   string `yaml:"id"`   // "s1" or "s2"
	Port int    `yaml:"port"` // REST API port
}

type PeerConfig struct {
	Host string `yaml:"host"` // peer's WebSocket host
	Port int    `yaml:"port"` // peer's WebSocket port
	Role string `yaml:"role"` // "server" or "client"
}

type APIConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type KeystoreConfig struct {
	Dir        string `yaml:"dir"`        // directory for encrypted key shares
	Passphrase string `yaml:"passphrase"` // encryption passphrase (PoC only — use KMS in prod)
}

type TronConfig struct {
	Network  string `yaml:"network"`  // "nile" or "mainnet"
	FullNode string `yaml:"fullnode"` // TRON full node URL
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
