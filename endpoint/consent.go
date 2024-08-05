package endpoint

import (
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wingfeng/idx-oauth2/service"
)

type ConsentController struct {
	ConsentService service.ConsentService
}

func (ctrl *ConsentController) PostConsent(ctx *gin.Context) {
	scopes := ctx.PostFormArray("scope")
	principle := ctx.GetString(Const_Principle)
	if strings.EqualFold(principle, "") {
		ctx.JSON(401, gin.H{
			"error": "Unauthorized",
		})
	}
	client_id := ctx.PostForm("client_id")
	slog.Debug("PostConsent", "client_id", client_id, "principle", principle, "scopes", scopes)
	err := ctrl.ConsentService.SaveConsents(client_id, principle, scopes)
	if err != nil {
		ctx.JSON(500, gin.H{
			"message": "Consent save error",
			"error":   err.Error(),
		})
		return
	}
	ctx.Redirect(302, ctx.PostForm("uri"))
}
