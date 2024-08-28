package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wingfeng/idx-oauth2/model"
	"github.com/wingfeng/idx-oauth2/service"
)

func TestValidateReturnUri(t *testing.T) {
	client := &model.Client{
		RedirectUris: []string{
			"http://example.com:*/*",
			"http://example.org",
			"http://example.com",
			"http://example.com/*",
		},
	}

	// Test case 1: Valid return URI
	uri := "http://example.com"
	assert.True(t, service.ValidateReturnUri(client, uri), "Expected true for valid return URI")
	// Test case 1: Valid return URI
	uri = "http://example.com/callback?role=admin"
	assert.True(t, service.ValidateReturnUri(client, uri), "Expected true for valid return URI")
	uri = "http://example.com:8899/callback"
	assert.True(t, service.ValidateReturnUri(client, uri), "Expected true for valid return URI")
	// Test case 2: Invalid return URI
	uri = "http://example.invalid"
	assert.False(t, service.ValidateReturnUri(client, uri), "Expected false for invalid return URI")

	// Test case 3: Empty return URI
	uri = ""
	assert.False(t, service.ValidateReturnUri(client, uri), "Expected false for empty return URI")

	// Test case 4: Return URI not in client's list
	uri = "http://example.invalid"
	assert.False(t, service.ValidateReturnUri(client, uri), "Expected false for return URI not in client's list")
}
