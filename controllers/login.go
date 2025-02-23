package controllers

import (
	"context"
	"fmt"
	"log"

	"github.com/Nerzal/gocloak/v13"
)

func loginUser(username, password string) {
	client := gocloak.NewClient("http://localhost:8080")
	ctx := context.Background()

	// Replace with your client ID and client secret (if applicable)
	clientID := "your_client_id"
	clientSecret := "your_client_secret" // leave empty if public client

	// Perform the login (Resource Owner Password Credentials Grant)
	jwt, err := client.Login(ctx, clientID, clientSecret, "myrealm", username, password)
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}

	fmt.Printf("Access Token: %s\n", jwt.AccessToken)
	// You can now use this token for authorization in your application
}
