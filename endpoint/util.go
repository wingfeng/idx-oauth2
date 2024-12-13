package endpoint

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/wingfeng/idx-oauth2/conf"
)

func getIssuer(ctx *gin.Context, config *conf.Config) string {
	issuer := fmt.Sprintf("%s://%s/%s/", config.Scheme, ctx.Request.Host, config.TenantPath)

	return issuer
}

func AuthMiddleware(ctx *gin.Context) {
	principle := ""
	session := sessions.Default(ctx)

	v := session.Get(Const_Principle)
	if v != nil {
		principle = v.(string)
	}
	if !strings.EqualFold(principle, "") {
		ctx.Set(Const_Principle, principle)
		slog.Debug("User Authorized", "user", principle)
	}

	ignorePaths := []string{"/login", "/oauth2/token", "/oauth2/authorize", "/oauth2/device",
		"/.well-known/openid-configuration",
		"/.well-known/jwks",
		"/oauth2/userinfo",
		"/oauth2/introspect",
		"/index",
		"/",
		"/index.html",
	}

	for _, ignorePath := range ignorePaths {

		if strings.LastIndex(ctx.Request.URL.Path, ignorePath) != -1 {
			ctx.Next()
			return
		}
	}

	if strings.EqualFold(principle, "") {

		link := ctx.Request.URL.String()
		slog.Info("Principle empty begin redirect", "principle", principle, "link", link)
		ctx.HTML(401, "login.html", gin.H{
			"redirect": link,
		})

		return
	}

	ctx.Next()
}

func ShowLogin(ctx *gin.Context, redirect string, config *conf.Config) {
	ctx.HTML(401, "login.html", gin.H{
		"redirect": redirect,
		"tenant":   config.TenantPath,
		"group":    config.EndpointGroup,
	})
}
