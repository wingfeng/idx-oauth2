package oauth2

import (
	"github.com/wingfeng/idx-oauth2/conf"
	"github.com/wingfeng/idx-oauth2/endpoint"
	"github.com/wingfeng/idx-oauth2/repo"
	"github.com/wingfeng/idx-oauth2/service"

	"github.com/gin-gonic/gin"
)

type Tenant struct {
	ClientService    service.ClientService
	AuthorizeService service.AuthorizeService
	TokenService     service.TokenService
	UserService      service.UserService
	ConsentService   service.ConsentService
	Config           *conf.Config
	//controller
	authorizeCtrl    *endpoint.AuthorizeController
	tokenCtrl        *endpoint.TokenController
	wellKnowCtrl     *endpoint.WellknownController
	userInfoCtrl     *endpoint.UserInfoController
	introspectCtrl   *endpoint.IntrospectController
	deviceCtrl       *endpoint.DeviceCodeController
	consentCtrl      *endpoint.ConsentController
	indexCtrl        *endpoint.IndexController
	loginCtrl        *endpoint.LoginController
	logoutCtrl       *endpoint.LogoutController
	revokeCtrl       *endpoint.RevokeController
	endSessionCtrl   *endpoint.EndSessionController
	checkSessionCtrl *endpoint.CheckSessionController
}

func NewTenant(config *conf.Config,
	userRepo repo.UserRepository,
	clientRepo repo.ClientRepository,
	authRepo repo.AuthorizationRepository,
	consentRepo repo.ConsentRepository,
	tokenService service.TokenService,
	jwks *conf.JWKS,
) *Tenant {

	userService := &service.DefaultUserService{
		UserRepository: userRepo,
	}

	clientService := service.NewClientService(clientRepo)
	consentService := &service.DefaultConsentService{Repo: consentRepo}
	authorizeService := service.NewAuthorizeService(tokenService, config, authRepo, userService)
	s := &Tenant{
		Config:           config,
		UserService:      userService,
		ClientService:    clientService,
		TokenService:     tokenService,
		AuthorizeService: authorizeService,
		ConsentService:   consentService,
	}
	s.authorizeCtrl = &endpoint.AuthorizeController{
		AuthorizeService: s.AuthorizeService,
		ClientService:    clientService,
		ConsentSevice:    s.ConsentService,
		Config:           config,
	}
	s.wellKnowCtrl = &endpoint.WellknownController{Config: config,
		JWKS: jwks,
	}
	s.userInfoCtrl = &endpoint.UserInfoController{AuthorizeService: authorizeService, UserService: userService}
	s.tokenCtrl = &endpoint.TokenController{
		AuthorizeService: authorizeService,
		ClientService:    clientService,
		Config:           config,
	}
	s.introspectCtrl = &endpoint.IntrospectController{AuthorizeService: authorizeService,
		ClientService: clientService}

	s.deviceCtrl = &endpoint.DeviceCodeController{
		AuthorizationService: authorizeService,
		ClientService:        clientService,
		Config:               config,
	}
	s.revokeCtrl = &endpoint.RevokeController{
		AuthorizeService: s.AuthorizeService,
		ClientService:    s.ClientService,
		TokenService:     s.TokenService,
	}
	s.endSessionCtrl = &endpoint.EndSessionController{ClientService: clientService}
	s.checkSessionCtrl = &endpoint.CheckSessionController{}

	s.consentCtrl = &endpoint.ConsentController{ConsentService: consentService}
	s.loginCtrl = &endpoint.LoginController{
		UserService: userService,
		Config:      config,
	}
	s.logoutCtrl = &endpoint.LogoutController{ClientService: clientService, Config: config}
	s.indexCtrl = &endpoint.IndexController{Config: config}
	return s
}

func (s *Tenant) InitOAuth2Router(router *gin.Engine, SessionHandler func(ctx *gin.Context)) {

	config := s.Config
	tenantGroup := router.Group(config.TenantPath)
	if SessionHandler != nil {
		tenantGroup.Use(SessionHandler)
	}
	tenantGroup.Use(endpoint.AuthMiddleware)

	tenantGroup.GET("/.well-known/openid-configuration", s.wellKnowCtrl.GetConfiguration)
	tenantGroup.GET(config.JwksURI, s.wellKnowCtrl.GetJWKS)
	tenantGroup.POST("/login", s.loginCtrl.PostLogin)
	tenantGroup.GET("/login", s.loginCtrl.LoginGet)
	tenantGroup.POST("/logout", s.logoutCtrl.Logout)
	tenantGroup.GET("/logout", s.logoutCtrl.Logout)

	tenantGroup.GET("/", s.indexCtrl.Index)
	tenantGroup.GET("/index.html", s.indexCtrl.Index)
	group := tenantGroup.Group(config.EndpointGroup)

	group.POST(config.AuthorizationEndpoint, s.authorizeCtrl.Authorize)
	group.GET(config.AuthorizationEndpoint, s.authorizeCtrl.Authorize)

	group.POST(config.TokenEndpoint, s.tokenCtrl.PostToken)

	group.GET(config.UserInfoEndpoint, s.userInfoCtrl.GetUserInfo)
	group.POST(config.UserInfoEndpoint, s.userInfoCtrl.GetUserInfo)

	group.POST(config.IntrospectionEndpoint, s.introspectCtrl.GetIntrospect)
	group.GET(config.IntrospectionEndpoint, s.introspectCtrl.GetIntrospect)
	//Device Endpoint

	group.POST(config.DeviceCodeEndpoint, s.deviceCtrl.GetDeviceCode)
	group.GET(config.DeviceCodeEndpoint, s.deviceCtrl.GetDeviceCode)
	group.GET(config.DeviceAuthorizationEndpoint, s.deviceCtrl.GetDeviceAuthorization)
	group.POST(config.DeviceAuthorizationEndpoint, s.deviceCtrl.PostDeviceAuthorization)

	group.POST(config.ConsentEndpoint, s.consentCtrl.PostConsent)

	group.POST(config.RevocationEndpoint, s.revokeCtrl.PostRevoke)
	group.GET(config.EndSessionEndpoint, s.endSessionCtrl.EndSession)

	group.GET(config.CheckSessionIframe, s.checkSessionCtrl.CheckSession)

}
