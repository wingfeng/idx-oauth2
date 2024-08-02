package request

import "strings"

type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" binding:"required"` //code token id_token, code map to AuthorizationCode flow, token,id_token map to implicit flow
	ClientId            string `form:"client_id" binding:"required"`
	ClientSecret        string `form:"client_secret"`
	RedirectUri         string `form:"redirect_uri" binding:"required"`
	Scope               string `form:"scope"`
	Nonce               string `form:"nonce"`
	State               string `form:"state"`
	ResponseMode        string `form:"response_mode"` //fragment, query,form_post
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
}

func (req *AuthorizeRequest) ResponseCode() bool {
	resp := strings.Split(req.ResponseType, " ")
	for _, resp := range resp {
		if strings.EqualFold(resp, "code") {
			return true
		}
	}
	return false
}
func (req *AuthorizeRequest) ResponseWithToken() bool {
	resp := strings.Split(req.ResponseType, " ")
	for _, resp := range resp {

		if strings.EqualFold(resp, "token") {
			return true
		}
	}
	return false
}
func (req *AuthorizeRequest) ResponseWithIdToken() bool {
	resp := strings.Split(req.ResponseType, " ")
	for _, resp := range resp {
		resp = strings.ToLower(resp)
		if strings.EqualFold(resp, "id_token") {
			return true
		}
	}
	return false
}
