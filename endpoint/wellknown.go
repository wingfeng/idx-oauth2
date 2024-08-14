package endpoint

import (
	"net/url"

	"github.com/wingfeng/idx-oauth2/conf"

	"github.com/gin-gonic/gin"
)

type WellknownController struct {
	Config *conf.Config
	JWKS   *conf.JWKS
}

// Well-known configuration
func (ctrl *WellknownController) GetConfiguration(ctx *gin.Context) {

	ctx.Header("Content-Type", "application/json")
	ctx.Header("Access-Control-Allow-Origin", "*")
	ctx.Header("Access-Control-Request-Method", "GET")
	config := *ctrl.Config //copy the config
	var err error

	config.Issuer = getIssuer(ctx, ctrl.Config)
	groupPath, _ := url.JoinPath(config.Issuer, config.EndpointGroup)
	config.JwksURI, _ = url.JoinPath(config.Issuer, ctrl.Config.JwksURI)

	config.AuthorizationEndpoint, _ = url.JoinPath(groupPath, ctrl.Config.AuthorizationEndpoint)
	config.TokenEndpoint, _ = url.JoinPath(groupPath, ctrl.Config.TokenEndpoint)
	config.CheckSessionIframe, _ = url.JoinPath(groupPath, ctrl.Config.CheckSessionIframe)
	config.IntrospectionEndpoint, _ = url.JoinPath(groupPath, ctrl.Config.IntrospectionEndpoint)
	config.RevocationEndpoint, _ = url.JoinPath(groupPath, ctrl.Config.RevocationEndpoint)
	config.UserInfoEndpoint, _ = url.JoinPath(groupPath, ctrl.Config.UserInfoEndpoint)
	config.EndSessionEndpoint, _ = url.JoinPath(groupPath, ctrl.Config.EndSessionEndpoint)
	config.DeviceCodeEndpoint, _ = url.JoinPath(groupPath, ctrl.Config.DeviceCodeEndpoint)
	config.DeviceAuthorizationEndpoint, err = url.JoinPath(groupPath, ctrl.Config.DeviceAuthorizationEndpoint)

	if err != nil {
		ctx.JSON(500, gin.H{"error": err.Error()})
	}
	ctx.JSON(200, config)
}
func (ctrl *WellknownController) GetJWKS(ctx *gin.Context) {
	ctx.JSON(200, ctrl.JWKS)
}
