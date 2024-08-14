package endpoint

import (
	"log/slog"
	"net/url"
	"strings"

	"github.com/wingfeng/idx-oauth2/conf"
	"github.com/wingfeng/idx-oauth2/model"
	"github.com/wingfeng/idx-oauth2/model/request"
	"github.com/wingfeng/idx-oauth2/model/response"
	"github.com/wingfeng/idx-oauth2/service"

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
	issuer := getIssuer(ctx, ctrl.Config)
	auth := ctrl.AuthorizationService.CreateDeviceAuthorization(req.ClientId, req.Scope, issuer)

	verifyUri, _ := url.JoinPath(ctrl.Config.EndpointGroup, ctrl.Config.DeviceAuthorizationEndpoint)
	verifyUri += "?" + "user_code=" + auth.UserCode
	fullPath := getIssuer(ctx, ctrl.Config) + verifyUri
	resp := &response.DeviceCodeResponse{
		DeviceCode:              auth.DeviceCode,
		ExpiresIn:               int64(ctrl.Config.DeviceCodeLifeTime),
		Interval:                5,
		Message:                 "Please visit the following URL to authorize the application: ",
		UserCode:                auth.UserCode,
		VerificationUri:         verifyUri,
		VerificationUriComplete: fullPath,
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
		ShowLogin(ctx, ctx.Request.URL.String(), ctrl.Config)
		return
	}
	slog.Debug("Valide Principle done", "principle", principle)
	auth := ctrl.AuthorizationService.GetAuthorizationByUserCode(ctx.Request.FormValue("user_code"))
	auth.PrincipalName = principle
	auth.UpdateExiresAt(ctrl.Config.TokenLifeTime)
	ctrl.AuthorizationService.Save(auth)
	ctx.HTML(200, "device_success.html", gin.H{
		"title": "IDX Home",
	},
	)
}
