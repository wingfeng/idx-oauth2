package endpoint

import (
	"strings"

	"github.com/wingfeng/idx-oauth2/service"

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

	headers := strings.Split(authHeader, " ")
	if headers[0] != "Bearer" || len(headers) != 2 {
		ctx.AbortWithStatus(401)
		return
	}
	token := headers[1]
	//validate access token and get principal

	authorize := c.AuthorizeService.GetAuthorizationByAccessToken(token)
	if authorize == nil {
		ctx.AbortWithStatus(401)
		return
	}
	user, err := c.UserService.GetUser(authorize.Subject)
	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	ctx.JSON(200, user)

}
