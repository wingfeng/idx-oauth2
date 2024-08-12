package request

type TokenRequest struct {
	ClientId     string `form:"client_id" binding:"required"`
	Scope        string `form:"scope"`
	GrantType    string `form:"grant_type" binding:"required"`
	Issuer       string `form:"-"`
	ClientSecret string `form:"client_secret"`
}

// use for tokenendpoint to validate authorization code flow request
type CodeFlowRequest struct {
	CodeVerifier string `form:"code_verifier"`
	Code         string `form:"code" binding:"required"`
	RedirectUri  string `form:"redirect_uri" binding:"required"`
	State        string `form:"state"`

	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
	Nonce               string `form:"nonce"`
	TokenRequest
}

type PasswordRequest struct {
	Password string `form:"password" binding:"required"`

	UserName string `form:"username" binding:"required"`
	TokenRequest
}
type RefreshTokenRequest struct {
	RefreshToken string `form:"refresh_token" binding:"required"`
	TokenRequest
}
type ClientCredentialsRequest struct {
	TokenRequest
}
type DeviceCodeTokenRequest struct {
	DeviceCode string `form:"device_code" binding:"required"`
	TokenRequest
}
