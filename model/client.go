package model

import "strings"

type IClient interface {
	GetScopes() []string

	GetClientId() string
	GetClientScope() string
	GetClientName() string
	GetGrantTypes() []string
	GetRequireConsent() bool
	GetRequirePKCE() bool
	GetRedirectUris() []string
	GetPostLogoutUris() []string
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
func (c *Client) GetClientScope() string {
	return c.ClientScope
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
	return []string{c.Secret}
}
func (c *Client) GetRequirePKCE() bool {
	return c.RequirePKCE
}
