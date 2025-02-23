package controllers

import (
	"fmt"
	"log"

	"github.com/Nerzal/gocloak/v13"
	"net/http"
    "github.com/gin-gonic/gin"
)

func RegisterUser(c *gin.Context) {
	var user struct {
        Username string `json:"username" binding:"required"`
        Email    string `json:"email" binding:"required"`
        Password string `json:"password" binding:"required"`
		Organization string `json:"organization" binding:"required"`
    }

    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
	// Initialize gocloak client pointing to your Keycloak instance.
	client := gocloak.NewClient("http://localhost:8080")
    ctx := c.Request.Context()

	// Log in as admin (or a service account with proper privileges)
	adminToken, err := client.LoginAdmin(ctx, "admin", "admin_password", "master")
	if err != nil {
		log.Fatalf("failed to login as admin: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to login as admin"})
        return
	}

	// Prepare user data
	newUser := gocloak.User{
		Username: gocloak.StringP(user.Username),
		Email:    gocloak.StringP(user.Email),
		Enabled:  gocloak.BoolP(true),
	}

	realmName := user.Organization

	// Create the user in your realm (e.g., "myrealm" as an orgranization)
	userID, err := client.CreateUser(ctx, adminToken.AccessToken, realmName, newUser)
	if err != nil {
		log.Fatalf("failed to create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
        return
	}
	
	fmt.Printf("Created user with ID: %s in realm: %s\n", userID, realmName)

	// Set the user's password
	err = client.SetPassword(ctx, adminToken.AccessToken, userID, realmName, user.Password, false)
	if err != nil {
		log.Fatalf("failed to set password for user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set password"})
        return
	}

	//return userID
	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
		"userID": userID,
	})
	// Optionally, assign roles to the user (see below)
}
