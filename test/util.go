package test

import (
	"encoding/base64"
	"fmt"
)

func generateBasicAuthHeader(username, password string) string {
	authStr := fmt.Sprintf("%s:%s", username, password)
	basicAuth := base64.StdEncoding.EncodeToString([]byte(authStr))
	return fmt.Sprintf("Basic %s", basicAuth)
}
