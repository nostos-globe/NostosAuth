package service

import (
	"time"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"

	"main/internal/models"
	"main/pkg/config"
)

type AuthService struct {
	Config *config.Config
}

func (s *AuthService) GenerateToken(user *models.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user.UserID,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
		"email": user.Email,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.Config.JWTSecret))
}

func (s *AuthService) GenerateRefreshToken(user *models.User) (string, error) {
    claims := jwt.MapClaims{
        "user_id": user.UserID,
        "email":   user.Email,
        "exp":     time.Now().Add(time.Hour * 24 * 30).Unix(), // 30 days
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(s.Config.JWTSecret + "_refresh"))
}

func (s *AuthService) ValidateAccessToken(tokenString string) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(s.Config.JWTSecret), nil
    })
}

func (s *AuthService) ValidateRefreshToken(tokenString string) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(s.Config.JWTSecret + "_refresh"), nil
    })
}
