package db

import (
	"fmt"
	"log"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"main/pkg/config"
)

func ConnectDB(cfg *config.Config) (*gorm.DB, error) {
	// Formatear la cadena de conexión
	log.Printf("Intentando conectar a la base de datos: host=%s user=%s dbname=%s port=%s",
		cfg.DBHost, cfg.DBUser, cfg.DBName, cfg.DBPort)

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)

	// Intentar conectar a la base de datos
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("error al conectar la base de datos: %w", err)
	}

	log.Println("Base de datos conectada y migraciones aplicadas correctamente.")
	return db, nil
}
