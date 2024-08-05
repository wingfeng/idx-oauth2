package endpoint

import (
	"fmt"

	"github.com/wingfeng/idx-oauth2/conf"

	"github.com/gin-gonic/gin"
)

type WellknownController struct {
	Config *conf.Config
	JWKS   *conf.JWKS
}

// Well-known configuration
func (ctrl *WellknownController) GetConfiguration(ctx *gin.Context) {

	r := ctx.Request

	ctx.Header("Content-Type", "application/json")
	ctx.Header("Access-Control-Allow-Origin", "*")
	ctx.Header("Access-Control-Request-Method", "GET")
	config := *ctrl.Config

	config.Issuer = fmt.Sprintf("%s://%s", config.Scheme, r.Host)
	config.JwksURI = fmt.Sprintf("%s%s", config.Issuer, ctrl.Config.JwksURI)
	config.AuthorizationEndpoint = fmt.Sprintf("%s%s", config.EndpointGroup, ctrl.Config.AuthorizationEndpoint)
	config.TokenEndpoint = fmt.Sprintf("%s%s", config.EndpointGroup, ctrl.Config.TokenEndpoint)
	config.CheckSessionIframe = fmt.Sprintf("%s%s", config.EndpointGroup, ctrl.Config.CheckSessionIframe)
	config.IntrospectionEndpoint = fmt.Sprintf("%s%s", config.EndpointGroup, ctrl.Config.IntrospectionEndpoint)
	config.RevocationEndpoint = fmt.Sprintf("%s%s", config.EndpointGroup, ctrl.Config.RevocationEndpoint)
	config.UserInfoEndpoint = fmt.Sprintf("%s%s", config.EndpointGroup, ctrl.Config.UserInfoEndpoint)
	config.EndSessionEndpoint = fmt.Sprintf("%s%s", config.EndpointGroup, ctrl.Config.EndSessionEndpoint)
	config.DeviceCodeEndpoint = fmt.Sprintf("%s%s", config.EndpointGroup, ctrl.Config.DeviceCodeEndpoint)
	config.DeviceAuthorizationEndpoint = fmt.Sprintf("%s%s", config.EndpointGroup, ctrl.Config.DeviceAuthorizationEndpoint)
	ctx.JSON(200, config)
}
func (ctrl *WellknownController) GetJWKS(ctx *gin.Context) {
	ctx.JSON(200, ctrl.JWKS)
}
