package test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/magiconair/properties/assert"
)

func Test_Hybridflow(t *testing.T) {
	router, _ := init_router()

	recorder := httptest.NewRecorder()
	query := make(url.Values)
	query.Add("response_type", "code id_token")
	query.Add("client_id", "hybrid_client")
	query.Add("client_secret", "secret")
	query.Add("redirect_uri", "http://localhost:9000/callback")
	query.Add("scope", "openid profile email")
	query.Add("nonce", "n-0S6_WzA2Mj")
	query.Add("state", "af0ifjsldkj")
	strQ := query.Encode()
	link := "/idx/oauth2/authorize?" + strQ
	req, _ := http.NewRequest("GET", link, nil)

	router.ServeHTTP(recorder, req)

	assert.Equal(t, recorder.Code, 401)

	form := make(url.Values)
	form.Add("username", "user1")
	form.Add("password", "password1")
	req, err := http.NewRequest("POST", "/idx/login", bytes.NewBufferString(form.Encode()))
	if err != nil {
		t.Logf("Error:%s", err.Error())
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	cookies := recorder.Result().Cookies()
	assert.Equal(t, recorder.Code, 302)
	req, _ = http.NewRequest("GET", "/idx/oauth2/authorize?"+strQ, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Body:\n %s", recorder.Body.String())
	assert.Equal(t, recorder.Code, 302)
}
