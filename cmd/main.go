package main

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/nats-io/nats.go"

	"log"
	"main/internal/api"
	dbRepo "main/internal/db"
	"main/internal/events"
	"main/internal/service"
	"main/pkg/config"
	"main/pkg/db"

	"github.com/gin-gonic/gin"
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
	nc, err := nats.Connect(cfg.NatsUrl)

	// Conectar a la base de datos
	database, err := db.ConnectDB(cfg)
	if err != nil {
		log.Fatalf("Error al conectar la base de datos: %v", err)
	}

	// Crear repositorio y servicios
	repo := &dbRepo.UserRepository{DB: database}
	publisher := events.NewPublisher(nc)
	authService := &service.AuthService{Config: cfg, UserRepo: repo}
	handler := &api.AuthHandler{UserRepo: repo, AuthService: authService, Events: publisher}

	// Iniciar Gin
	r := gin.Default()

	// Routes
	r.POST("/register", handler.Register)
	r.POST("/login", handler.Login)
	r.POST("/logout", handler.Logout)
	r.POST("/validate", handler.ValidateToken)
	r.POST("/forgot-password", handler.RequestPasswordReset)
	r.POST("/reset-password", handler.ResetPassword)
	r.POST("/update-password", handler.UpdatePassword)
	r.GET("/profile", handler.Profile)
	r.POST("/refresh-token", handler.RefreshToken)

	// Iniciar servidor
	log.Println("Servidor corriendo en http://localhost:8081")
	if err := r.Run(":8082"); err != nil {
		log.Fatalf("Error al iniciar el servidor: %v", err)
	}
}
