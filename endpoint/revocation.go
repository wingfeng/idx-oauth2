package endpoint

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wingfeng/idx-oauth2/model/request"
	"github.com/wingfeng/idx-oauth2/service"
)

type RevokeController struct {
	AuthorizeService service.AuthorizeService
	ClientService    service.ClientService
	TokenService     service.TokenService
}

func (c *RevokeController) PostRevoke(ctx *gin.Context) {
	req := request.RevokeRequest{}
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !c.ClientService.ValidateSecret(req.ClientId, req.ClientSecret) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id or secret"})
		return
	}
	var err error
	switch req.TokenTypeHint {
	case "access_token":
		err = c.revokeAccessToken(req)

	case "refresh_token":
		err = c.revokeRefreshToken(req)

	default:
		err = c.revokeAccessToken(req)
		if err != nil {
			err = c.revokeRefreshToken(req)
		}
	}
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (c *RevokeController) revokeRefreshToken(req request.RevokeRequest) error {
	auth := c.AuthorizeService.GetAuthorizationByRefreshToken(req.Token)
	if auth == nil || strings.EqualFold(auth.ClientId, req.ClientId) {
		return fmt.Errorf("invalid token")
	}
	newToken, err := c.TokenService.GenerateRefreshToken(auth)
	if err != nil {
		return err
	}
	auth.RefreshToken = newToken
	c.AuthorizeService.Save(auth)

	return nil
}

func (c *RevokeController) revokeAccessToken(req request.RevokeRequest) error {
	auth := c.AuthorizeService.GetAuthorizationByAccessToken(req.Token)
	if auth == nil || strings.EqualFold(auth.ClientId, req.ClientId) {
		return fmt.Errorf("invalid token")
	}
	newToken, err := c.TokenService.GenerateToken(auth)
	if err != nil {
		return err
	}
	auth.RefreshToken = newToken
	c.AuthorizeService.Save(auth)

	return nil
}
