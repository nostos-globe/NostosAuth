package config

import (
	"log"

	"github.com/joho/godotenv"
)

type Config struct {
	DBHost     string
	DBUser     string
	DBPassword string
	DBName     string
	DBPort     string
	JWTSecret  string
}

func LoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	return &Config{
		DBHost:     "localhost",
		DBUser:     "root",
		DBPassword: "root",
		DBName:     "nostos",
		DBPort:     "5432",
		JWTSecret:  "13ac1017-f3c7-4224-bfc2-e2d869e7e63e",
	}
}
