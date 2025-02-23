package main

import (
	"RandD-in-Keycloak-with-Golang/controllers"
	"RandD-in-Keycloak-with-Golang/middleware"
	_"context"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Public route (e.g., login or health check)
	r.POST("/RegisterUser", controllers.RegisterUser)

	// Protected routes
	protected := r.Group("/api")
	protected.Use(middleware.AuthMiddleware("user"))
	{
		protected.GET("/profile", func(c *gin.Context) {
			// Your protected endpoint logic here
			c.JSON(200, gin.H{"message": "Access granted to protected resource"})
		})
	}

	r.Run(":3000")
}
