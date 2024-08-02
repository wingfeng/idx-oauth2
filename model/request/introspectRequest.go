package request

type InstropectRequest struct {
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret"`
	Token        string `form:"token" binding:"required"`
}
