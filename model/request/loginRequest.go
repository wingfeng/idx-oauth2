package request

type LoginRequest struct {
	UserName string `form:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
	Redirect string `form:"redirect"`
}
