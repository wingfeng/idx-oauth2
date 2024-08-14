package endpoint

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wingfeng/idx-oauth2/conf"
)

type IndexController struct {
	Config *conf.Config
}

func (ctrl *IndexController) Index(ctx *gin.Context) {
	principle := ctx.GetString(Const_Principle)
	ctx.HTML(200, "index.html", gin.H{
		"title":      "IDX Home",
		"userName":   principle,
		"tenant":     ctrl.Config.TenantPath,
		"isLoggedIn": !strings.EqualFold(principle, ""),
	})
}
