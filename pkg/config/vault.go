package config

import (
    "fmt"
    "os"

    vault "github.com/hashicorp/vault/api"
)

type VaultConfig struct {
    Client *vault.Client
}

func InitVault() (*VaultConfig, error) {
    config := vault.DefaultConfig()
    config.Address = getVaultAddress()

    client, err := vault.NewClient(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create vault client: %v", err)
    }

    // Set Vault token from environment variable
    token := os.Getenv("VAULT_TOKEN")
    if token == "" {
        return nil, fmt.Errorf("VAULT_TOKEN environment variable not set")
    }
    client.SetToken(token)

    return &VaultConfig{Client: client}, nil
}

func (vc *VaultConfig) GetSecret(path, key string) (string, error) {
    secret, err := vc.Client.Logical().Read(path)
    if err != nil {
        return "", fmt.Errorf("failed to read secret: %v", err)
    }

    if secret == nil {
        return "", fmt.Errorf("secret not found at path: %s", path)
    }

    value, ok := secret.Data[key].(string)
    if !ok {
        return "", fmt.Errorf("key not found: %s", key)
    }

    return value, nil
}

func getVaultAddress() string {
    addr := os.Getenv("VAULT_ADDR")
    if addr == "" {
        return "http://localhost:8200"
    }
    return addr
}