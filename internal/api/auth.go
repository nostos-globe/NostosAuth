package api

import (
	"main/internal/db"
	"main/internal/models"
	"main/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type AuthHandler struct {
	UserRepo    *db.UserRepository
	AuthService *service.AuthService
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	hashedPassword, err := h.AuthService.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := &models.User{
		Name:         req.Name,
		Email:        req.Email,
		PasswordHash: hashedPassword,
	}

	if err := h.UserRepo.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	user, err := h.UserRepo.GetUserByEmail(req.Email)
	if err != nil || !h.AuthService.VerifyPassword(user.PasswordHash, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := h.AuthService.GenerateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	refreshToken, err := h.AuthService.GenerateRefreshToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	c.SetCookie(
		"auth_token",
		token,
		3600*24, // 24 hours
		"/",
		"",
		true, // Secure flag
		true, // HttpOnly flag
	)
	// Set only refresh token as httpOnly cookie (30 days)
	c.SetCookie(
		"refresh_token",
		refreshToken,
		3600*24*30,
		"/",
		"",
		true,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"message":     "Login successful",
		"accessToken": token,
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	// Clear access token cookie
	c.SetCookie(
		"auth_token",
		"",
		-1,
		"/",
		"",
		true,
		true,
	)

	// Clear refresh token cookie
	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		"",
		true,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

func (h *AuthHandler) UpdatePassword(c *gin.Context) {
	var req struct {
		Email       string `json:"email"`
		OldPassword string `json:"old password"`
		NewPassword string `json:"new password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	user, err := h.UserRepo.GetUserByEmail(req.Email)
	if err != nil || !h.AuthService.VerifyPassword(user.PasswordHash, req.OldPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	hashedPassword, err := h.AuthService.HashPassword(req.NewPassword)

	user.PasswordHash = hashedPassword

	if err := h.UserRepo.UpdateUser(user); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Get refresh token from cookie
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token provided"})
		return
	}

	// Validate refresh token
	token, err := h.AuthService.ValidateRefreshToken(refreshToken)
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Extract user claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse token claims"})
		return
	}

	// Get user from database
	userID := uint(claims["user_id"].(float64))
	user, err := h.UserRepo.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Generate new access token
	newToken, err := h.AuthService.GenerateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new token"})
		return
	}

	// Set new access token cookie
	c.SetCookie(
		"auth_token",
		newToken,
		3600*24,
		"/",
		"",
		true,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "Token refreshed successfully",
		"token":   newToken,
	})
}

func (h *AuthHandler) ValidateToken(c *gin.Context) {
	// Get access token from cookie
	tokenString, err := c.Cookie("auth_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
		return
	}

	// Validate the access token
	token, err := h.AuthService.ValidateAccessToken(tokenString)
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token is valid"})
}

func (h *AuthHandler) Profile(c *gin.Context) {
    tokenString, err := c.Cookie("auth_token")
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
        return
    }

    userID, err := h.AuthService.GetUserIDFromToken(tokenString)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
        return
    }

    user, err := h.UserRepo.GetUserByID(userID)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "User found successfully",
        "user": gin.H{
            "user_id":               user.UserID,
            "name":                  user.Name,
            "email":                 user.Email,
            "failed_login_attempts": user.FailedLoginAttempts,
            "account_locked":        user.AccountLocked,
            "avatar_url":            user.AvatarURL,
            "registration_date":     user.RegistrationDate,
        },
    })
}
