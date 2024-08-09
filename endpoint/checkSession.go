package endpoint

import "github.com/gin-gonic/gin"

type CheckSessionController struct {
}

func (ctrl *CheckSessionController) CheckSession(ctx *gin.Context) {
	ctx.HTML(200, "check_session.html", gin.H{})
}
