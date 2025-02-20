package api

import (
	"main/internal/db"
	"main/internal/models"
	"main/internal/service"
	"net/http"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gin-gonic/gin"
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

    // Generate access token (JWT)
    token, err := h.AuthService.GenerateToken(user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }

    // Generate refresh token
    refreshToken, err := h.AuthService.GenerateRefreshToken(user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
        return
    }

    // Set access token cookie (24 hours)
    c.SetCookie(
        "auth_token",
        token,
        3600 * 24,
        "/",
        "",
        true,
        true,
    )

    // Set refresh token cookie (30 days)
    c.SetCookie(
        "refresh_token",
        refreshToken,
        3600 * 24 * 30,
        "/",
        "",
        true,
        true,
    )

    c.JSON(http.StatusOK, gin.H{
        "message": "Login successful",
        "token": token,
    })
}

// Add this new endpoint for token refresh
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
        3600 * 24,
        "/",
        "",
        true,
        true,
    )

    c.JSON(http.StatusOK, gin.H{
        "message": "Token refreshed successfully",
        "token": newToken,
    })
}
func (h *AuthHandler) Profile(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	user, err := h.UserRepo.GetUserByEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid User"})
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
