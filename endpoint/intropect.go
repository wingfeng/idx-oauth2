package endpoint

import (
	"github.com/wingfeng/idx-oauth2/model/request"
	"github.com/wingfeng/idx-oauth2/model/response"
	"github.com/wingfeng/idx-oauth2/service"

	"github.com/gin-gonic/gin"
)

type IntrospectController struct {
	AuthorizeService service.AuthorizeService
	ClientService    service.ClientService
}

func (c *IntrospectController) GetIntrospect(ctx *gin.Context) {
	req := &request.InstropectRequest{}
	if err := ctx.ShouldBind(req); err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if !c.ClientService.ValidateSecret(req.ClientID, req.ClientSecret) {
		ctx.JSON(400, gin.H{"error": "invalid_client"})
		return
	}

	auth := c.AuthorizeService.GetAuthorizationByAccessToken(req.Token)
	if auth == nil {
		ctx.JSON(400, gin.H{"error": "invalid_token"})
		return
	}
	result := &response.IntropectResponse{
		Active:   true,
		Scope:    auth.Scope,
		Subject:  auth.Subject,
		UserName: auth.PrincipalName,
		ClientId: auth.ClientId,
		Exp:      auth.ExpiresAt,
	}
	ctx.JSON(200, result)
}
