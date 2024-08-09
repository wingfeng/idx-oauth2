package request

type EndSessionRequest struct {
	IdTokenHint           string `form:"id_token_hint" binding:"required"`
	PostLogoutRedirectUri string `form:"post_logout_redirect_uri" binding:"required"`
	State                 string `form:"state"`
	ClientId              string `form:"client_id" binding:"required"`
}
