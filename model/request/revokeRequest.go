package request

type RevokeRequest struct {
	Token         string `json:"token" form:"token" binding:"required"`
	ClientId      string `json:"client_id" form:"client_id" binding:"required"`
	ClientSecret  string `json:"client_secret" form:"client_secret"`
	TokenTypeHint string `json:"token_type_hint" form:"token_type_hint"`
}
