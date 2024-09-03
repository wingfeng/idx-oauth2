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
	// AuthorizationCode authorization_code grant type
	AuthorizationCode GrantType = "authorization_code"
	// PasswordCredentials password grant type
	PasswordCredentials GrantType = "password"
	// ClientCredentials client_credentials grant type
	ClientCredentials GrantType = "client_credentials"
	// Refreshing refresh_token grant type
	Refreshing GrantType = "refresh_token"
	//Implicit implicit grant type
	Implicit GrantType = "implicit"
	// DeviceCode device_code grant type
	DeviceCode GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)
