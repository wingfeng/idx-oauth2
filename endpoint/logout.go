package endpoint

import "github.com/gin-gonic/gin"

func Logout(ctx *gin.Context) {
	//remove principle cookise
	ctx.SetCookie(Const_Principle, "", -1, "/", "", false, true)
	ctx.Redirect(302, "/")
}
