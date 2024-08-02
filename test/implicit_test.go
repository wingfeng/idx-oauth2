package test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/magiconair/properties/assert"
)

func Test_Implicit(t *testing.T) {
	router, _ := init_router()
	recorder := httptest.NewRecorder()
	query := make(url.Values)
	query.Add("response_type", "token id_token")
	query.Add("client_id", "implicit_client")
	query.Add("client_secret", "secret")
	query.Add("redirect_uri", "http://localhost:9000/callback")
	query.Add("scope", "openid profile email")
	query.Add("nonce", "n-0S6_WzA2Mj")
	query.Add("state", "af0ifjsldkj")
	strQ := query.Encode()
	link := "/oauth2/authorize?" + strQ
	req, _ := http.NewRequest("GET", link, nil)
	router.ServeHTTP(recorder, req)

	assert.Equal(t, recorder.Code, 401)

	form := make(url.Values)
	form.Add("username", "user1")
	form.Add("password", "password1")
	req, _ = http.NewRequest("POST", "/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Referer", link)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	cookies := recorder.Result().Cookies()
	assert.Equal(t, recorder.Code, 302)
	req, _ = http.NewRequest("GET", link, nil)

	for _, c := range cookies {
		req.AddCookie(c)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Body:\n %s", recorder.Body.String())
	assert.Equal(t, recorder.Code, 302)
}
