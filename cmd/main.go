package main

import (
	"log"
	"main/internal/api"
	dbRepo "main/internal/db"
	"main/internal/service"
	"main/pkg/config"
	"main/pkg/db"

	"github.com/gin-gonic/gin"
)

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

	// Rutas
	r.POST("/register", handler.Register)
	r.POST("/login", handler.Login)
	//r.POST("/reset-password", handler.ResetPassword)
	r.POST("/update-password", handler.UpdatePassword)
	r.POST("/profile", handler.Profile)

	// Iniciar servidor
	log.Println("Servidor corriendo en http://localhost:8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Error al iniciar el servidor: %v", err)
	}
}
