package controllers

import (
    "context"
    "log"
    "net/http"

    "github.com/Nerzal/gocloak/v13"
    "github.com/gin-gonic/gin"
)

// LoginUser processes login requests by verifying user credentials
func LoginUser(c *gin.Context) {
    type loginRequest struct {
        Username string `json:"username" binding:"required"`
        Password string `json:"password" binding:"required"`
    }

    var req loginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    client := gocloak.NewClient("http://localhost:8080")
    ctx := context.Background()

    // Attempt to log in with the provided credentials
    jwt, err := client.Login(
        ctx,
        adminCredentials.ClientID,
        adminCredentials.ClientSecret,
        adminCredentials.RealmName, // could be your “myapp” realm instead of “master”
        req.Username,
        req.Password,
    )
    if err != nil {
        log.Printf("Login failed: %v", err)
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        return
    }

    // Return tokens
    c.JSON(http.StatusOK, gin.H{
        "message":          "Login successful",
        "id_token":         jwt.IDToken,
        "token_type":       jwt.TokenType,
        "access_token":     jwt.AccessToken,
        "expires_in":       jwt.ExpiresIn,
        "refresh_token":    jwt.RefreshToken,
        "refresh_expires":  jwt.RefreshExpiresIn,
        "session_state":    jwt.SessionState,
        "scope":            jwt.Scope,
        "not-before-policy": jwt.NotBeforePolicy,
    })
}
