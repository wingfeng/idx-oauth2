package endpoint

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/wingfeng/idx-oauth2/model/request"
	"github.com/wingfeng/idx-oauth2/service"

	"github.com/gin-gonic/gin"
)

const Const_Principle = "Principal"

type LoginController struct {
	UserService service.UserService
}

func (ctrl *LoginController) PostLogin(ctx *gin.Context) {
	var loginRequest request.LoginRequest
	if err := ctx.ShouldBind(&loginRequest); err != nil {
		ctx.HTML(401, "login.html", gin.H{"error": err.Error(),
			"redirect": loginRequest.Redirect,
		})
		return
	}
	if ctrl.UserService.VerifyPassword(loginRequest.UserName, loginRequest.Password) {

		session := sessions.Default(ctx)
		session.Set(Const_Principle, loginRequest.UserName)
		session.Save()
		link := loginRequest.Redirect

		if strings.EqualFold(link, "") {
			link = "/"
		}
		slog.Info("User logined", "user", loginRequest.UserName, "redirect to", link)
		ctx.Redirect(302, link)
	} else {
		ctx.HTML(401, "login.html", gin.H{
			"error":    "invalid username or password",
			"redirect": loginRequest.Redirect,
		})
		return
	}
}
func (ctrl *LoginController) LoginGet(ctx *gin.Context) {

	link := ctx.Request.Referer()
	slog.Info("Redirect from ", "Referer", link)
	if strings.EqualFold(link, "") || strings.Index(link, "/login") == 0 {
		link = "/"
	}
	redirect := ctx.Query("redirect")
	if strings.EqualFold(redirect, "") {
		redirect = link
	}
	ctx.HTML(http.StatusFound, "login.html", gin.H{
		"redirect": redirect,
	})
}
