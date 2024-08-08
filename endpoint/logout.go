package endpoint

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/wingfeng/idx-oauth2/service"
)

type LogoutController struct {
	ClientService service.ClientService
}

func (ctrl *LogoutController) Logout(ctx *gin.Context) {
	//remove principle from session
	session := sessions.Default(ctx)
	session.Delete(Const_Principle)
	session.Save()
	ctx.Redirect(302, "/")
}
