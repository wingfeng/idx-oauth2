package constants

// ResponseType the type of authorization request
type ResponseType string

// define the type of authorization request
const (
	Code    ResponseType = "code"
	Token   ResponseType = "token"
	IDToken ResponseType = "id_token"
)

func (rt ResponseType) String() string {
	return string(rt)
}

// GrantType authorization model
type GrantType string

// define authorization model
const (
	AuthorizationCode   GrantType = "authorization_code"
	PasswordCredentials GrantType = "password"
	ClientCredentials   GrantType = "client_credentials"
	Refreshing          GrantType = "refresh_token"
	Implicit            GrantType = "implicit"
	DeviceCode          GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)
