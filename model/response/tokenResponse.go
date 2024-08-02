package response

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"` //Bearer
	Scope        string `json:"scope"`
}
