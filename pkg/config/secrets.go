package config

import (
    "log"
    "sync"
)

var (
    secretsManager *SecretsManager
    once          sync.Once
)

type SecretsManager struct {
    vault *VaultConfig
}

func GetSecretsManager() *SecretsManager {
    once.Do(func() {
        vault, err := InitVault()
        if err != nil {
            log.Fatalf("Failed to initialize Vault: %v", err)
        }
        secretsManager = &SecretsManager{vault: vault}
    })
    return secretsManager
}

func (sm *SecretsManager) LoadSecrets() map[string]string {
    secrets := make(map[string]string)
    
    // Define your secret paths and keys
    secretPaths := map[string]string{
        "DB_HOST":     "secret/data/database/host",
        "DB_USER":     "secret/data/database/user",
        "DB_PASSWORD": "secret/data/database/password",
        "DB_NAME":     "secret/data/database/name",
        "DB_PORT":     "secret/data/database/port",
        "JWT_SECRET":  "secret/data/jwt/secret",
    }

    for env, path := range secretPaths {
        value, err := sm.vault.GetSecret(path, "value")
        if err != nil {
            log.Printf("Warning: Failed to load secret for %s: %v", env, err)
            continue
        }
        secrets[env] = value
    }

    return secrets
}