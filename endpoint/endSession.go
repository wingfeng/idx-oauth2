package endpoint

import (
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/wingfeng/idx-oauth2/model/request"
	"github.com/wingfeng/idx-oauth2/service"
)

type EndSessionController struct {
	ClientService service.ClientService
}

func (c *EndSessionController) EndSession(ctx *gin.Context) {
	var req request.EndSessionRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}
	err := c.ClientService.ValidateLogoutUri(req.ClientId, req.PostLogoutRedirectUri)
	if err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
	}
	session := sessions.Default(ctx)
	session.Delete(Const_Principle)
	session.Save()
	url := req.PostLogoutRedirectUri

	if req.State != "" {
		if strings.Contains(req.PostLogoutRedirectUri, "?") {
			url = url + "&state=" + req.State
		} else {
			url = url + "?state=" + req.State
		}

	}
	ctx.HTML(200, "endsession.html", gin.H{
		"state": req.State,
		"url":   url,
	})
}
