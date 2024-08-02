package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	constants "github.com/wingfeng/idx/oauth2/const"
	"github.com/wingfeng/idx/oauth2/model/response"

	"github.com/magiconair/properties/assert"
)

func Test_DeviceCodeGrant(t *testing.T) {
	router, tenant := init_router()
	recorder := httptest.NewRecorder()
	query := make(url.Values)

	query.Add("grant_type", string(constants.DeviceCode))
	query.Add("client_id", "device_code_client")
	query.Add("client_secret", "secret")
	query.Add("scope", "openid email profile")
	link := fmt.Sprintf("%s%s", tenant.Config.EndpointGroup, tenant.Config.DeviceCodeEndpoint)
	req, _ := http.NewRequest("GET", link+"?"+query.Encode(), nil) // bytes.NewBufferString(query.Encode()))
	//req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Response:\n %s", recorder.Body.String())

	assert.Equal(t, recorder.Code, 200)
	resp := &response.DeviceCodeResponse{}
	json.Unmarshal(recorder.Body.Bytes(), resp)
	//login
	// Prepare login post
	form := make(url.Values)
	form.Add("username", "user1")
	form.Add("password", "password1")
	req, err := http.NewRequest("POST", "/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Referer", link)

	if err != nil {
		t.Logf("Error:%s", err.Error())
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	cookies := recorder.Result().Cookies()

	assert.Equal(t, 302, recorder.Code)
	query = make(url.Values)
	query.Add("user_code", resp.UserCode)
	link = fmt.Sprintf("%s%s", tenant.Config.EndpointGroup, tenant.Config.DeviceAuthorizationEndpoint)
	req, _ = http.NewRequest("POST", link, bytes.NewBufferString(query.Encode()))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Response:\n %s", recorder.Body.String())
	//Get token from token endpoint
	query = make(url.Values)

	query.Add("device_code", resp.DeviceCode)

	query.Add("grant_type", string(constants.DeviceCode))
	query.Add("client_id", "device_code_client")
	query.Add("client_secret", "secret")

	req, _ = http.NewRequest("POST", "/oauth2/token", bytes.NewBufferString(query.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	t.Logf("Response:\n %s", recorder.Body.String())

	assert.Equal(t, recorder.Code, 200)
}
