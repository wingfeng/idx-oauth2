package conf

import constants "github.com/wingfeng/idx-oauth2/const"

type Config struct {
	TokenLifeTime                      int64    `json:"-"`
	DeviceCodeLifeTime                 int      `json:"-"`
	RefreshTokenLifeTime               int64    `json:"-"`
	Scheme                             string   `json:"-"`
	EndpointGroup                      string   `json:"-"`
	ConsentEndpoint                    string   `json:"-"`
	Issuer                             string   `json:"issuer"`
	JwksURI                            string   `json:"jwks_uri"`
	AuthorizationEndpoint              string   `json:"authorization_endpoint"`
	TokenEndpoint                      string   `json:"token_endpoint"`
	UserInfoEndpoint                   string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                 string   `json:"end_session_endpoint"`
	CheckSessionIframe                 string   `json:"check_session_iframe"`
	RevocationEndpoint                 string   `json:"revocation_endpoint"`
	IntrospectionEndpoint              string   `json:"introspection_endpoint"`
	DeviceAuthorizationEndpoint        string   `json:"device_authorization_endpoint"`
	DeviceCodeEndpoint                 string   `json:"device_code_endpoint"`
	FrontchannelLogoutSupported        bool     `json:"frontchannel_logout_supported"`
	FrontchannelLogoutSessionSupported bool     `json:"frontchannel_logout_session_supported"`
	BackchannelLogoutSupported         bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported  bool     `json:"backchannel_logout_session_supported"`
	ScopesSupported                    []string `json:"scopes_supported"`
	ClaimsSupported                    []string `json:"claims_supported"`
	GrantTypesSupported                []string `json:"grant_types_supported"`
	ResponseTypesSupported             []string `json:"response_types_supported"`
	ResponseModesSupported             []string `json:"response_modes_supported"`
	TokenEndpointAuthMethodsSupported  []string `json:"token_endpoint_auth_methods_supported"`
	IDTokenSigningAlgValuesSupported   []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypesSupported              []string `json:"subject_types_supported"`
	CodeChallengeMethodsSupported      []string `json:"code_challenge_methods_supported"`
	RequestParameterSupported          bool     `json:"request_parameter_supported"`
}

func DefaultConfig() *Config {
	return &Config{
		Scheme:                             "http",
		TokenLifeTime:                      3600,
		RefreshTokenLifeTime:               24 * 3600,
		DeviceCodeLifeTime:                 600,
		JwksURI:                            "/.well-known/jwks",
		EndpointGroup:                      "/oauth2",
		ConsentEndpoint:                    "/consent",
		AuthorizationEndpoint:              "/authorize",
		TokenEndpoint:                      "/token",
		UserInfoEndpoint:                   "/userinfo",
		EndSessionEndpoint:                 "/logout",
		CheckSessionIframe:                 "/check_session",
		RevocationEndpoint:                 "/revoke",
		IntrospectionEndpoint:              "/introspect",
		DeviceCodeEndpoint:                 "/device",
		DeviceAuthorizationEndpoint:        "/device_authorization",
		FrontchannelLogoutSupported:        false,
		FrontchannelLogoutSessionSupported: false,
		BackchannelLogoutSupported:         false,
		ScopesSupported:                    []string{"openid", "profile", "email"},
		GrantTypesSupported:                []string{"authorization_code", "refresh_token", "client_credentials", "password", string(constants.DeviceCode)}, // "urn:ietf:params:oauth:grant-type:jwt-bearer"},
		ResponseTypesSupported:             []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token", "none"},
		ResponseModesSupported:             []string{"query", "fragment", "form_post"},
		TokenEndpointAuthMethodsSupported:  []string{"client_secret_post", "client_secret_basic"}, // "client_secret_jwt", "private_key_jwt"},
		IDTokenSigningAlgValuesSupported:   []string{"RS256"},                                     //, "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"},

		SubjectTypesSupported:         []string{"public"}, //, "pairwise"}, //https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
		CodeChallengeMethodsSupported: []string{"S256", "plain"},
		RequestParameterSupported:     true,
	}
}
