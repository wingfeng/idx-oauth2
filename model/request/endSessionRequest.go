package request

type EndSessionRequest struct {
	IdTokenHint           string `form:"id_token_hint" `
	PostLogoutRedirectUri string `form:"post_logout_redirect_uri" `
	State                 string `form:"state"`
	ClientId              string `form:"client_id"`
}
