package test

import (
	"encoding/base64"
	"fmt"
)

// generateBasicAuthHeader generates an HTTP Basic Authentication header.
//
// This function takes a username and password, and returns a string that conforms to the HTTP Basic Authentication standard for the Authorization request header.
// HTTP Basic Authentication is a simple authentication mechanism that separates the username and password with a colon, then encodes the entire string in Base64.
//
// Parameters:
//
//	username: A string representing the username for authentication.
//	password: A string representing the password for authentication.
//
// Returns:
//
//	A formatted Basic Authentication string intended to be added to an HTTP request header.
func generateBasicAuthHeader(username, password string) string {
	// Combine the username and password into an authentication string
	authStr := fmt.Sprintf("%s:%s", username, password)
	// Encode the authentication string in Base64
	basicAuth := base64.StdEncoding.EncodeToString([]byte(authStr))
	// Format the string as used in HTTP request headers
	return fmt.Sprintf("Basic %s", basicAuth)
}
