package middleware

import (
    _"context"
    "net/http"
    "strings"

  
    "github.com/golang-jwt/jwt/v5"
	"github.com/Nerzal/gocloak/v13"
    "context"
    "github.com/gin-gonic/gin"
)

// AuthMiddleware verifies the token and checks if the user has the required role.
func AuthMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			c.Abort()
			return
		}

		// Extract the token
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader { // If Bearer prefix is missing
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		// Initialize Keycloak client
		client := gocloak.NewClient("http://localhost:8080")
		ctx := context.Background()
		realm := "your-realm-name"
		clientID := "your-client-id"
		clientSecret := "your-client-secret"

		// Validate token
		rptResult, err := client.RetrospectToken(ctx, tokenString, clientID, clientSecret, realm)
		if err != nil || !*rptResult.Active {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Extract user roles from the token claims
		_, claims, err  := client.DecodeAccessToken(ctx, tokenString, realm)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Could not parse token"})
			c.Abort()
			return
		}

		roles := extractRoles(claims) // Function to extract roles
		if requiredRole != "" && !contains(roles, requiredRole) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Function to extract roles from Keycloak JWT claims
func extractRoles(token *jwt.MapClaims) []string {
    if token == nil {
		return []string{}
	}

    convertedClaims := map[string]interface{}(*token)

	if realmAccess, ok := convertedClaims["realm_access"].(map[string]interface{}); ok {
		if roles, found := realmAccess["roles"].([]interface{}); found {
			var roleList []string
			for _, r := range roles {
				if role, ok := r.(string); ok {
					roleList = append(roleList, role)
				}
			}
			return roleList
		}
	}
	return []string{}
}

// Helper function to check if a role exists in the list
func contains(roles []string, requiredRole string) bool {
	for _, r := range roles {
		if r == requiredRole {
			return true
		}
	}
	return false
}
