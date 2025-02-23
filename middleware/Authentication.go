package middleware

import (
    _"context"
    "net/http"
    "strings"

    "github.com/dgrijalva/jwt-go"
    "github.com/gin-gonic/gin"
)

// AuthMiddleware verifies the token and checks if the user has the required role.
func AuthMiddleware(requiredRole string) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        if tokenString == authHeader {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
            return
        }

        // Parse the token (for simplicity, we’re skipping signature verification here; in production, verify it using the public key)
        token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            return
        }

        if claims, ok := token.Claims.(jwt.MapClaims); ok {
            // Look for realm_access and roles
            if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
                if roles, ok := realmAccess["roles"].([]interface{}); ok {
                    for _, role := range roles {
                        if role == requiredRole {
                            c.Next()
                            return
                        }
                    }
                }
            }
        }

        c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
    }
}
