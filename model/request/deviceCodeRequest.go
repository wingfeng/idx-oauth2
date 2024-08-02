package request

type DeviceCodeRequest struct {
	ClientId     string `form:"client_id" binding:"required"`
	Scope        string `form:"scope" binding:"required"`
	ClientSecret string `form:"client_secret"`
}
