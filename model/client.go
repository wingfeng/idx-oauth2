package model

import "strings"

// IClient defines the client interface, including a series of operations related to client configuration.
type IClient interface {
	// GetScopes returns a list of scopes that the client is allowed to access.
	GetScopes() []string

	// GetClientId returns the unique identifier of the client.
	GetClientId() string

	// GetClientName returns the name of the client.
	GetClientName() string

	// GetGrantTypes returns a list of authorization types supported by the client.
	GetGrantTypes() []string

	// GetRequireConsent returns whether user consent is required.
	GetRequireConsent() bool

	// GetRequirePKCE returns whether PKCE (Proof Key for Code Exchange) is required.
	GetRequirePKCE() bool

	// GetRedirectUris returns a list of URIs to which the client redirects.
	GetRedirectUris() []string

	// GetPostLogoutUris returns a list of URIs to which the client redirects after logout.
	GetPostLogoutUris() []string

	// GetSecret returns a list of secrets associated with the client.
	GetSecret() []string
}

type Client struct {
	Id             string   `json:"id"`
	ClientId       string   `json:"client_id"`
	Secret         string   `json:"secret"`
	ClientScope    string   `json:"client_scope"`
	ClientName     string   `json:"client_name"`
	GrantTypes     []string `json:"grant_type"`
	RequireConsent bool     `json:"require_consent"`
	RequirePKCE    bool     `json:"require_pkce"`
	RedirectUris   []string `json:"redirect_uris"`

	PostLogoutUris []string `json:"post_logout_uri"`
	// 创建时间
	CreatedAt string `json:"created_at"`
	// 更新时间
	UpdatedAt string `json:"updated_at"`
}

func (c *Client) GetScopes() []string {
	return strings.Split(c.ClientScope, " ")
}
func (c *Client) GetClientId() string {
	return c.ClientId
}

func (c *Client) GetClientName() string {
	return c.ClientName
}
func (c *Client) GetGrantTypes() []string {
	return c.GrantTypes
}
func (c *Client) GetRequireConsent() bool {
	return c.RequireConsent
}
func (c *Client) GetRedirectUris() []string {
	return c.RedirectUris
}
func (c *Client) GetPostLogoutUris() []string {
	return c.PostLogoutUris
}
func (c *Client) GetSecret() []string {
	if strings.EqualFold(c.Secret, "") {
		return []string{}
	} else {
		return []string{c.Secret}
	}
}
func (c *Client) GetRequirePKCE() bool {
	return c.RequirePKCE
}
