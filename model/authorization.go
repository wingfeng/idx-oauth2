package model

import (
	"strings"
	"time"
)

type Authorization struct {
	Id            string `json:"id"`
	ClientId      string `json:"client_id"`
	PrincipalName string `json:"principal_name"`
	Subject       string `json:"subject"`
	GrantType     string `json:"grant_type"`
	ResponseType  string `json:"response_type"`
	Scope         string `json:"scope"`
	//	Attributes          map[string]interface{} `json:"attributes"`
	Code                string `json:"code"`
	Nonce               string `json:"nonce"`
	AccessToken         string `json:"access_token"`
	RefreshToken        string `json:"refresh_token"`
	IDToken             string `json:"id_token"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	DeviceCode          string `json:"device_code"`
	ExpiresAt           int64  `json:"expires_at"` //Unix timestamp
	UserCode            string `json:"user_code"`
}

func (a *Authorization) IncludeOpenId() bool {
	return strings.Contains(a.Scope, "openid")
}

func (a *Authorization) UpdateExiresIn(lifeTime int64) {

	a.ExpiresAt = time.Now().Add(time.Second * time.Duration(lifeTime)).Unix()
}
