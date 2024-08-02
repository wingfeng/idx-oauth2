package test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/magiconair/properties/assert"
)

func Test_PasswordGrant(t *testing.T) {
	router, _ := init_router()
	recorder := httptest.NewRecorder()
	query := make(url.Values)

	query.Add("grant_type", "password")
	query.Add("client_id", "password_client")
	query.Add("client_secret", "secret")
	query.Add("username", "user1")
	query.Add("scope", "openid email profile")
	query.Add("password", "password1")
	req, _ := http.NewRequest("POST", "/oauth2/token", bytes.NewBufferString(query.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Response:\n %s", recorder.Body.String())

	assert.Equal(t, recorder.Code, 200)
}
