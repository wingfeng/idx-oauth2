package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/wingfeng/idx-oauth2/model/response"

	"github.com/magiconair/properties/assert"
)

func TestUserInfoEndpoint(t *testing.T) {
	router, _ := init_router()

	query := make(url.Values)

	query.Add("grant_type", "password")
	query.Add("client_id", "password_client")
	query.Add("client_secret", "secret")
	query.Add("username", "user1")
	query.Add("scope", "openid email profile")
	query.Add("password", "password1")
	req, _ := http.NewRequest("POST", "/idx/oauth2/token", bytes.NewBufferString(query.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Response:\n %s", recorder.Body.String())

	assert.Equal(t, recorder.Code, 200)
	var response response.TokenResponse
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	assert.Equal(t, err, nil)
	req, _ = http.NewRequest("GET", "/idx/oauth2/userinfo", nil)
	req.Header.Add("Authorization", "Bearer "+response.AccessToken)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Response:\n %s", recorder.Body.String())
	assert.Equal(t, recorder.Code, 200)
}
