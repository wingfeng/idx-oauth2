package endpoint

import (
	"log/slog"
	"net/url"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/wingfeng/idx-oauth2/conf"
	"github.com/wingfeng/idx-oauth2/model/request"
	"github.com/wingfeng/idx-oauth2/service"

	"github.com/gin-gonic/gin"
)

const Const_Principle = "Principal"

type ILoginController interface {
	PostLogin(ctx *gin.Context)
	GetLogin(ctx *gin.Context)
}
type LoginController struct {
	UserService service.UserService
	Config      *conf.Config
}

func (ctrl *LoginController) PostLogin(ctx *gin.Context) {
	loginRequest := &request.LoginRequest{}

	if err := ctx.ShouldBind(&loginRequest); err != nil {
		ctx.HTML(401, "login.html", gin.H{
			"error":    err.Error(),
			"redirect": loginRequest.Redirect,
			"tenant":   ctrl.Config.TenantPath,
			"group":    ctrl.Config.EndpointGroup,
		})
		return
	}
	if ctrl.UserService.VerifyPassword(loginRequest.UserName, loginRequest.Password) {

		session := sessions.Default(ctx)
		session.Set(Const_Principle, loginRequest.UserName)
		session.Save()
		link := loginRequest.Redirect

		if strings.EqualFold(link, "") {
			link, _ = url.JoinPath(ctrl.Config.TenantPath, "/")
		}
		slog.Info("User logined", "user", loginRequest.UserName, "redirect to", link)
		ctx.Redirect(302, link)
	} else {
		ctx.HTML(401, "login.html", gin.H{
			"error":    "invalid username or password",
			"redirect": loginRequest.Redirect,
			"tenant":   ctrl.Config.TenantPath,
			"group":    ctrl.Config.EndpointGroup,
		})
		return
	}
}
func (ctrl *LoginController) GetLogin(ctx *gin.Context) {
	ShowLogin(ctx, ctx.Query("redirect"), ctrl.Config)
}
