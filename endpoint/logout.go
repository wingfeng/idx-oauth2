package endpoint

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/wingfeng/idx-oauth2/conf"
	"github.com/wingfeng/idx-oauth2/service"
)

type ILogoutController interface {
	Logout(ctx *gin.Context)
}

type LogoutController struct {
	ClientService service.ClientService
	Config        *conf.Config
}

func (ctrl *LogoutController) Logout(ctx *gin.Context) {
	//remove principle from session
	session := sessions.Default(ctx)
	session.Delete(Const_Principle)
	session.Save()
	//root, _ := url.JoinPath(ctrl.Config.TenantPath, "/")
	ctx.Redirect(302, "")
}
