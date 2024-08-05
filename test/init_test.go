package test

import (
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/golang-jwt/jwt"
	"github.com/wingfeng/idx-oauth2/conf"
	constants "github.com/wingfeng/idx-oauth2/const"
	"github.com/wingfeng/idx-oauth2/core"
	"github.com/wingfeng/idx-oauth2/endpoint"
	"github.com/wingfeng/idx-oauth2/model"
	"github.com/wingfeng/idx-oauth2/repo"
	"github.com/wingfeng/idx-oauth2/service"
	"github.com/wingfeng/idx-oauth2/service/impl"
	"github.com/wingfeng/idx-oauth2/utils"

	"github.com/gin-gonic/gin"
)

func init_router() (*gin.Engine, *core.Tenant) {
	config := conf.DefaultConfig()
	secret, _ := utils.HashPassword("secret")
	clientRepo := repo.NewInMemoryClientRepository([]model.Client{
		{Id: "client1", ClientId: "code_client", ClientName: "client1", RequireConsent: false, ClientScope: "openid email profile ", Secret: "", GrantTypes: []string{"authorization_code", "refresh_token"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client2", ClientId: "implicit_client", ClientName: "client2", ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{"implicit"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client3", ClientId: "hybrid_client", ClientName: "client3", ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{"authorization_code", "implicit"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client4", ClientId: "password_client", ClientName: "client4", ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{"password"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client5", ClientId: "device_code_client", ClientName: "client5", ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{string(constants.DeviceCode)}, RedirectUris: []string{"http://localhost:9000/callback"}},
	})
	router := gin.Default()
	router.LoadHTMLGlob("../static/*.html")
	group := router.Group(config.EndpointGroup)
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))

	group.Use(func(ctx *gin.Context) {
		//		ctx.Set(endpoint.Const_Principle, "admin")
		session := sessions.Default(ctx)
		var principle string
		v := session.Get(endpoint.Const_Principle)
		if v != nil {
			principle = v.(string)
		}
		if !strings.EqualFold(principle, "") {
			ctx.Set(endpoint.Const_Principle, principle)
		}

		ctx.Next()
	})
	tokenService := impl.NewJwtTokenService(jwt.SigningMethodHS256, []byte("mysecret"), func(userName string, scope string) map[string]interface{} {
		return map[string]interface{}{
			"role": "manager",
		}
	})
	tokenService.TokenLifeTime = config.TokenLifeTime

	userService := &service.DefaultUserService{UserRepository: buildUserRepo()}
	authRepo := repo.NewInMemoryAuthorizeRepository()
	consentRepo := &repo.InMemoryConsentRepository{
		Consents: make(map[string]map[string][]string),
	}

	tenant := core.NewTenant(config, buildUserRepo(), clientRepo, authRepo, consentRepo, tokenService, nil)

	loginCtrl := &endpoint.LoginController{UserService: userService}
	router.POST("/login", loginCtrl.PostLogin)
	tenant.InitOAuth2Router(group, router)

	return router, tenant
}
func buildUserRepo() repo.UserRepository {
	pwdHash, _ := utils.HashPassword("password1")
	return repo.NewInMemoryUserRepository([]*model.User{
		{Id: "user1", UserName: "user1", Email: "user1@gmail.com", PasswordHash: pwdHash, Role: "manager"},
		{Id: "user2", UserName: "user2", Email: "user2@gmail.com", PasswordHash: pwdHash},
	})
}
