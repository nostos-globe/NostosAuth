package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (s *AuthService) HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed), err
}

func (s *AuthService) VerifyPassword(hashed, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) == nil
}

func (s *AuthService) CreatePasswordResetLink(email string) (string, error) {
	user, err := s.UserRepo.GetUserByEmail(email)
	if err != nil {
		return "", err
	}

	// Generate a secure random token
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	resetToken := hex.EncodeToString(token)

	// Store token and expiry (1 hour from now)
	user.ResetToken = resetToken
	user.ResetTokenExpiry = time.Now().Add(1 * time.Hour)

	if err := s.UserRepo.UpdateUser(user); err != nil {
		return "", err
	}

	// In production, this would be your frontend URL
	resetLink := fmt.Sprintf("https://your-frontend-url/reset-password?token=%s", resetToken)
	return resetLink, nil
}

func (s *AuthService) ResetPasswordWithToken(token, newPassword string) error {
	// Find user by reset token
	user, err := s.UserRepo.GetUserByResetToken(token)
	if err != nil {
		return err
	}

	// Check if token is expired
	if time.Now().After(user.ResetTokenExpiry) {
		return fmt.Errorf("reset token has expired")
	}

	// Hash new password
	hashedPassword, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update password and clear reset token
	user.PasswordHash = hashedPassword
	user.ResetToken = ""
	user.ResetTokenExpiry = time.Time{}

	return s.UserRepo.UpdateUser(user)
}
