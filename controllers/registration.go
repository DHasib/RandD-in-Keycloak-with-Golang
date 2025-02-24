package controllers

import (
	_"fmt"
	"log"
	"context"

	"github.com/Nerzal/gocloak/v13"
	"net/http"
    "github.com/gin-gonic/gin"
)

var adminCredentials = struct {
    AdminUsername string
    AdminPassword string
    RealmName     string
	ClientID 	  string
	ClientSecret  string
}{
    AdminUsername: "admin",
    AdminPassword: "admin_password",
    RealmName:     "master",
	ClientID:      "admin-cli",
	ClientSecret:  "admin_secret",
}

func RegisterUser(c *gin.Context) {
	type reqBody struct {
        // AdminUsername    string `json:"admin_username" binding:"required"`  // Keycloak master or realm admin
        // AdminPassword    string `json:"admin_password" binding:"required"`
        // RealmName        string `json:"realm_name" binding:"required"`      // Usually "myapp"
        OrgName          string `json:"org_name" binding:"required"`
        OrgAdminUsername string `json:"org_admin_username" binding:"required"`
        OrgAdminEmail    string `json:"org_admin_email" binding:"required"`
        OrgAdminPassword string `json:"org_admin_password" binding:"required"`
        // ClientID         string `json:"client_id" binding:"required"`
        // ClientSecret     string `json:"client_secret"`
    }

	var body reqBody
    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }


	// Initialize gocloak client pointing to your Keycloak instance.
	client := gocloak.NewClient("http://localhost:8080")
    // ctx := c.Request.Context()
	ctx := context.Background()

	// 1. Login as the realm admin
	adminToken, err := client.LoginAdmin(ctx, adminCredentials.AdminUsername, adminCredentials.AdminPassword, adminCredentials.RealmName)
	if err != nil {
		log.Fatalf("failed to login as admin: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to login as admin"})
        return
	}

	// 2. Check if group exists, else create in the realm
    groupName := body.OrgName
	group, err := getOrCreateGroup(ctx, client, adminToken.AccessToken, adminCredentials.RealmName, groupName)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create/find group"})
        return
    }

	 // 3. Create the org admin user
	 userID, err := createUserInRealm(ctx, client, adminToken.AccessToken, adminCredentials.RealmName, body.OrgAdminUsername, body.OrgAdminEmail)
	 if err != nil {
		 c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		 return
	 }

	 // 4. Set password for the org admin user
	 err = client.SetPassword(ctx, adminToken.AccessToken, userID, adminCredentials.RealmName, body.OrgAdminPassword, false)
	 if err != nil {
		 c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set user password"})
		 return
	 }

	 // 5. Assign user to the organization group
	 err = client.AddUserToGroup(ctx, adminToken.AccessToken, adminCredentials.RealmName, userID, *group.ID)
	 if err != nil {
		 c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user to group"})
		 return
	 }

	 orgAdminName := body.OrgName + "_admin"
	 newRole := gocloak.Role{
        Name: &orgAdminName,
        // Optional fields:
        // Description: gocloak.StringP("A custom realm role"),
        // Composite: gocloak.BoolP(false),
        // ClientRole: gocloak.BoolP(false),
    }

    roleID, err := client.CreateRealmRole(ctx, adminToken.AccessToken, adminCredentials.RealmName, newRole)
    if err != nil {
        log.Fatalf("Failed to create realm role: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create realm role"})
		 return
    }
	if roleID == "" {
		log.Fatalf("Failed to create realm role: %v", roleID)
	}
	 

	 // 6. Assign 'org_admin' role (assuming it exists at the realm level)
	 err = addRealmRoleToUser(ctx, client, adminToken.AccessToken, adminCredentials.RealmName, userID, orgAdminName)
	 if err != nil {
		 log.Printf("Failed to assign org_admin role: %v", err)
		 c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign org_admin role"})
		 return
	 }

	  // 7. Login as the new user to get tokens
	  jwt, err := client.Login(ctx, adminCredentials.ClientID, adminCredentials.ClientSecret, adminCredentials.RealmName, body.OrgAdminUsername, body.OrgAdminPassword)
	  if err != nil {
		  c.JSON(http.StatusUnauthorized, gin.H{"error": "Could not login as new org admin"})
		  return
	  }

	  //create session to hold all that data and return it


	  c.JSON(http.StatusOK, gin.H{
        "message": "Organization registered successfully",
        "org_name": groupName,
		"org_id": *group.ID,
		"org_admin_id": userID,
		"org_admin_username": body.OrgAdminUsername,
		"org_admin_email": body.OrgAdminEmail,
		"org_admin_password": body.OrgAdminPassword,

        "user_id": userID,
		"id_token": jwt.IDToken,
		"token_type": jwt.TokenType,
        "access_token": jwt.AccessToken,
		"expires_in": jwt.ExpiresIn,
        "refresh_token": jwt.RefreshToken,
		"refresh_expires_in": jwt.RefreshExpiresIn,
        "roles": []string{"org_admin"}, // or fetch dynamically
		"not-before-policy": jwt.NotBeforePolicy,
		"session_state": jwt.SessionState,
		"scope": jwt.Scope,
    	})

   {
			// // Prepare user data
			// newUser := gocloak.User{
			// 	Username: gocloak.StringP(user.Username),
			// 	Email:    gocloak.StringP(user.Email),
			// 	Enabled:  gocloak.BoolP(true),
			// }

			// realmName := user.Organization

			// // Create the user in your realm (e.g., "myrealm" as an orgranization)
			// userID, err := client.CreateUser(ctx, adminToken.AccessToken, realmName, newUser)
			// if err != nil {
			// 	log.Fatalf("failed to create user: %v", err)
			// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			//     return
			// }
			
			// fmt.Printf("Created user with ID: %s in realm: %s\n", userID, realmName)

			// // Set the user's password
			// err = client.SetPassword(ctx, adminToken.AccessToken, userID, realmName, user.Password, false)
			// if err != nil {
			// 	log.Fatalf("failed to set password for user: %v", err)
			// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set password"})
			//     return
			// }

			// //return userID
			// c.JSON(http.StatusOK, gin.H{
			// 	"message": "User created successfully",
			// 	"userID": userID,
			// })
			// Optionally, assign roles to the user (see below)
   }
}

func getOrCreateGroup(ctx context.Context, client *gocloak.GoCloak, token, realm, groupName string) (*gocloak.Group, error) {
    // Search for group by name
    groups, err := client.GetGroups(ctx, token, realm, gocloak.GetGroupsParams{
        Search: &groupName,
    })
    if err != nil {
        return nil, err
    }

    for _, g := range groups {
        if g.Name != nil && *g.Name == groupName {
            return g, nil // already exists
        }
    }

    // Create new group
    newGroup := gocloak.Group{
        Name: &groupName,
    }

    groupID, err := client.CreateGroup(ctx, token, realm, newGroup)
    if err != nil {
        return nil, err
    }

    // Retrieve it back
    createdGroup, err := client.GetGroup(ctx, token, realm, groupID)
    if err != nil {
        return nil, err
    }
    return createdGroup, nil
}

func createUserInRealm(ctx context.Context, client *gocloak.GoCloak, token, realm, username, email string) (string, error) {
    newUser := gocloak.User{
        Username: &username,
        Email:    &email,
        Enabled:  gocloak.BoolP(true),
    }
    userID, err := client.CreateUser(ctx, token, realm, newUser)
    return userID, err
}
func addRealmRoleToUser(ctx context.Context, client *gocloak.GoCloak, token, realm, userID, roleName string) error {
    // Retrieve the role by name
    role, err := client.GetRealmRole(ctx, token, realm, roleName)
    if err != nil {
        return err
    }
    // Assign role to user
    return client.AddRealmRoleToUser(ctx, token, realm, userID, []gocloak.Role{*role})
}