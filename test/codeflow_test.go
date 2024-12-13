package test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/magiconair/properties/assert"
)

func Test_CodeflowWithPKCE(t *testing.T) {
	router, _ := init_router()
	recorder := httptest.NewRecorder()
	query := make(url.Values)
	verifier := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWJI0qhD4Q5QA"
	query.Add("response_type", "code")
	query.Add("client_id", "code_client")

	query.Add("redirect_uri", "http://localhost:9000/callback")
	query.Add("scope", "openid profile email")
	query.Add("nonce", "n-0S6_WzA2Mj")
	query.Add("state", "af0ifjsldkj")
	query.Add("code_challenge", verifier)
	query.Add("code_challenge_method", "plain")
	strQ := query.Encode()
	authorizeLink := "/idx/oauth2/authorize?" + strQ
	req, _ := http.NewRequest("GET", authorizeLink, nil)

	router.ServeHTTP(recorder, req)

	assert.Equal(t, recorder.Code, 401)
	// Prepare login post
	form := make(url.Values)
	form.Add("username", "user1")
	form.Add("password", "password1")
	req, err := http.NewRequest("POST", "/idx/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Referer", authorizeLink)

	if err != nil {
		t.Logf("Error:%s", err.Error())
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	cookies := recorder.Result().Cookies()

	assert.Equal(t, 302, recorder.Code)
	//Post Consent page
	form = make(url.Values)
	form.Add("client_id", "code_client")
	form.Add("scope", "openid")
	form.Add("scope", "profile")
	form.Add("scope", "email")
	form.Add("uri", authorizeLink)
	req, _ = http.NewRequest("POST", "/idx/oauth2/consent", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, 302)
	req, _ = http.NewRequest("GET", authorizeLink, nil)

	for _, c := range cookies {
		req.AddCookie(c)
	}

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	recorder.Flush()
	header := recorder.Header()
	t.Logf("Authorize Response Body:%s", recorder.Body.String())
	assert.Equal(t, recorder.Code, 302)
	// t.Logf("Resp Redirect:%v", header["Location"])
	callbackURI, _ := url.Parse(header["Location"][0])

	t.Logf("CallBack link:%s", callbackURI.String())

	code := callbackURI.Query().Get("code")
	query = make(url.Values)

	query.Add("code", code)
	query.Add("redirect_uri", "http://localhost:9000/callback")
	query.Add("grant_type", "authorization_code")
	query.Add("client_id", "code_client")
	query.Add("client_secret", "secret")
	query.Add("code_verifier", verifier)
	req, _ = http.NewRequest("POST", "/idx/oauth2/token", bytes.NewBufferString(query.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", generateBasicAuthHeader("code_client", "secret"))
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Response:\n %s", recorder.Body.String())

	assert.Equal(t, recorder.Code, 200)
}
func Test_Codeflow(t *testing.T) {
	router, _ := init_router()

	recorder := httptest.NewRecorder()
	query := make(url.Values)

	query.Add("response_type", "code")
	query.Add("client_id", "code_client")
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
	// Prepare login post
	form := make(url.Values)
	form.Add("username", "user1")
	form.Add("password", "password1")
	req, err := http.NewRequest("POST", "/idx/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Referer", link)

	if err != nil {
		t.Logf("Error:%s", err.Error())
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	cookies := recorder.Result().Cookies()

	assert.Equal(t, 302, recorder.Code)
	//Prepare redirect to /oauth2/authorize
	header := recorder.Header()

	req, _ = http.NewRequest("GET", link, nil)

	for _, c := range cookies {
		req.AddCookie(c)
	}

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	recorder.Flush()
	header = recorder.Header()
	t.Logf("Response Body:%s", recorder.Body.String())
	assert.Equal(t, 302, recorder.Code)
	// t.Logf("Resp Redirect:%v", header["Location"])
	callbackURI, _ := url.Parse(header["Location"][0])

	t.Logf("CallBack link:%s", callbackURI.String())

	code := callbackURI.Query().Get("code")
	query = make(url.Values)

	query.Add("code", code)
	query.Add("redirect_uri", "http://localhost:9000/callback")
	query.Add("grant_type", "authorization_code")
	query.Add("client_id", "code_client")
	query.Add("client_secret", "secret")
	req, _ = http.NewRequest("POST", "/idx/oauth2/token", bytes.NewBufferString(query.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Response: %s", recorder.Body.String())

	assert.Equal(t, recorder.Code, 200)
}
func Test_CodeNoSecretflow(t *testing.T) {
	router, _ := init_router()
	client_id := "nosecret_client"
	recorder := httptest.NewRecorder()
	query := make(url.Values)

	query.Add("response_type", "code")
	query.Add("client_id", client_id)
	query.Add("redirect_uri", "http://localhost:9000/callback")
	query.Add("scope", "openid profile email")
	query.Add("nonce", "n-0S6_WzA2Mj")
	query.Add("state", "af0ifjsldkj")

	strQ := query.Encode()
	link := "/idx/oauth2/authorize?" + strQ
	req, _ := http.NewRequest("GET", link, nil)

	router.ServeHTTP(recorder, req)

	assert.Equal(t, recorder.Code, 401)
	// Prepare login post
	form := make(url.Values)
	form.Add("username", "user1")
	form.Add("password", "password1")
	req, err := http.NewRequest("POST", "/idx/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Referer", link)

	if err != nil {
		t.Logf("Error:%s", err.Error())
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	cookies := recorder.Result().Cookies()

	assert.Equal(t, 302, recorder.Code)
	//Prepare redirect to /oauth2/authorize

	req, _ = http.NewRequest("GET", link, nil)

	for _, c := range cookies {
		req.AddCookie(c)
	}

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	recorder.Flush()
	header := recorder.Header()
	t.Logf("Response Body:%s", recorder.Body.String())
	assert.Equal(t, 302, recorder.Code)
	// t.Logf("Resp Redirect:%v", header["Location"])
	callbackURI, _ := url.Parse(header["Location"][0])

	t.Logf("CallBack link:%s", callbackURI.String())

	code := callbackURI.Query().Get("code")
	query = make(url.Values)

	query.Add("code", code)
	query.Add("redirect_uri", "http://localhost:9000/callback")
	query.Add("grant_type", "authorization_code")
	query.Add("client_id", client_id)
	req, _ = http.NewRequest("POST", "/oauth2/token", bytes.NewBufferString(query.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Response: %s", recorder.Body.String())

	assert.Equal(t, recorder.Code, 200)
}
