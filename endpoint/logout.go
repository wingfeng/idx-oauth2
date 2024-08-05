package endpoint

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func Logout(ctx *gin.Context) {
	//remove principle cookise
	session := sessions.Default(ctx)
	session.Delete(Const_Principle)
	session.Save()
	ctx.Redirect(302, "/")
}
