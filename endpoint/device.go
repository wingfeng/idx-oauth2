package endpoint

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/wingfeng/idx/oauth2/conf"
	"github.com/wingfeng/idx/oauth2/model"
	"github.com/wingfeng/idx/oauth2/model/request"
	"github.com/wingfeng/idx/oauth2/model/response"
	"github.com/wingfeng/idx/oauth2/service"

	"github.com/gin-gonic/gin"
)

type DeviceCodeController struct {
	AuthorizationService service.AuthorizeService
	ClientService        service.ClientService
	Config               *conf.Config
}

func (ctrl *DeviceCodeController) GetDeviceCode(ctx *gin.Context) {
	var req request.DeviceCodeRequest
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if !ctrl.ClientService.ValidateSecret(req.ClientId, req.ClientSecret) {
		ctx.JSON(401, gin.H{"error": "invalid_client or secret"})
		return
	}
	client := &model.Client{ClientId: req.ClientId,
		Secret:      req.ClientSecret,
		ClientScope: req.Scope,
	}
	if err := ctrl.ClientService.ValidateClient(client); err != nil {
		ctx.JSON(401, gin.H{"error": err.Error()})
		return
	}
	auth := ctrl.AuthorizationService.GenerateDeviceAuthorization(req.ClientId, req.Scope)

	verifyUri := fmt.Sprintf("%s%s?%s=%s", ctrl.Config.EndpointGroup, ctrl.Config.DeviceAuthorizationEndpoint, "user_code", auth.UserCode)
	resp := &response.DeviceCodeResponse{
		DeviceCode:      auth.DeviceCode,
		ExpiresIn:       int64(ctrl.Config.DeviceCodeLifeTime),
		Interval:        5,
		Message:         "Please visit the following URL to authorize the application: ",
		UserCode:        auth.UserCode,
		VerificationUri: verifyUri,
	}
	ctx.JSON(200, resp)
}

func (ctrl *DeviceCodeController) GetDeviceAuthorization(ctx *gin.Context) {
	userCode := ctx.Query("user_code")
	ctx.HTML(200, "device.html", gin.H{
		"title":    "IDX Home",
		"UserCode": userCode,
	})
}
func (ctrl *DeviceCodeController) PostDeviceAuthorization(ctx *gin.Context) {
	principle := ctx.GetString(Const_Principle)
	//require login when principle is empty
	if strings.EqualFold(principle, "") {
		ctx.HTML(401, "login.html", gin.H{
			"error":    "unauthorized",
			"redirect": ctx.Request.URL.String(),
		})
		return
	}
	slog.Debug("Valide Principle done", "principle", principle)
	auth := ctrl.AuthorizationService.GetAuthorizationByUserCode(ctx.Request.FormValue("user_code"))
	auth.PrincipalName = principle
	auth.UpdateExiresIn(ctrl.Config.TokenLifeTime)
	ctrl.AuthorizationService.Save(auth)
	ctx.HTML(200, "device_success.html", gin.H{
		"title": "IDX Home",
	},
	)
}
