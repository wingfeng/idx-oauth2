package endpoint

import (
	"github.com/wingfeng/idx/oauth2/service"

	"github.com/gin-gonic/gin"
)

type UserInfoController struct {
	AuthorizeService service.AuthorizeService
	UserService      service.UserService
}

func (c *UserInfoController) GetUserInfo(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.AbortWithStatus(401)
		return
	}

	token := authHeader[7:]
	//validate access token and get principal
	authorize := c.AuthorizeService.GetAuthorizationByAccessToken(token)
	user, err := c.UserService.GetUser(authorize.Subject)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	ctx.JSON(200, user)

}
