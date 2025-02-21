package main

import (
	"os"
    "github.com/joho/godotenv"

	"github.com/gin-gonic/gin"
	"log"
	"main/internal/api"
	dbRepo "main/internal/db"
	"main/internal/service"
	"main/pkg/config"
	"main/pkg/db"
)

func init() {
    // Load .env file first
    if err := godotenv.Load(); err != nil {
        log.Printf("Warning: .env file not found or error loading it: %v", err)
    }

    // Initialize Vault
    secretsManager := config.GetSecretsManager()
    if secretsManager != nil {
        secrets := secretsManager.LoadSecrets()
        // Set environment variables from Vault
        for key, value := range secrets {
            os.Setenv(key, value)
        }
    } else {
        log.Println("Falling back to environment variables")
    }
}

func main() {
	// Cargar configuración
	cfg := config.LoadConfig()

	// Conectar a la base de datos
	database, err := db.ConnectDB(cfg)
	if err != nil {
		log.Fatalf("Error al conectar la base de datos: %v", err)
	}

	// Crear repositorio y servicios
	repo := &dbRepo.UserRepository{DB: database}
	authService := &service.AuthService{Config: cfg}
	handler := &api.AuthHandler{UserRepo: repo, AuthService: authService}

	// Iniciar Gin
	r := gin.Default()

	// Routes
    r.POST("/register", handler.Register)
    r.POST("/login", handler.Login)
    r.POST("/logout", handler.Logout)
    r.POST("/validate", handler.ValidateToken)
    r.POST("/update-password", handler.UpdatePassword) 
    r.GET("/profile", handler.Profile)
    r.POST("/refresh-token", handler.RefreshToken)

	// Iniciar servidor
	log.Println("Servidor corriendo en http://localhost:8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Error al iniciar el servidor: %v", err)
	}
}
