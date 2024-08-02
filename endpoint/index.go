package endpoint

import (
	"strings"

	"github.com/gin-gonic/gin"
)

func Index(ctx *gin.Context) {
	principle := ctx.GetString(Const_Principle)
	ctx.HTML(200, "index.html", gin.H{
		"title":      "IDX Home",
		"userName":   principle,
		"isLoggedIn": !strings.EqualFold(principle, ""),
	})
}
