package endpoint

import (
	"fmt"
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/wingfeng/idx-oauth2/conf"
)

func getIssuer(ctx *gin.Context, config *conf.Config) string {
	issuer := fmt.Sprintf("%s://%s", config.Scheme, ctx.Request.Host)
	slog.Debug("Issuer", "Issuer", issuer)
	return issuer
}
