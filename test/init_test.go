package test

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/golang-jwt/jwt"
	oauth2 "github.com/wingfeng/idx-oauth2"
	"github.com/wingfeng/idx-oauth2/conf"
	constants "github.com/wingfeng/idx-oauth2/const"
	"github.com/wingfeng/idx-oauth2/service"

	"github.com/wingfeng/idx-oauth2/model"
	"github.com/wingfeng/idx-oauth2/repo"
	"github.com/wingfeng/idx-oauth2/service/impl"
	"github.com/wingfeng/idx-oauth2/utils"

	"github.com/gin-gonic/gin"
)

func init_router() (*gin.Engine, *oauth2.Tenant) {
	config := conf.DefaultConfig()
	secret, _ := utils.HashPassword("secret")
	clientRepo := repo.NewInMemoryClientRepository([]model.Client{
		{Id: "client1", ClientId: "code_client", ClientName: "client1", RequireConsent: false, ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{"authorization_code", "refresh_token"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client1", ClientId: "nosecret_client", ClientName: "client1", RequireConsent: false, ClientScope: "openid email profile ", GrantTypes: []string{"authorization_code", "refresh_token"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client2", ClientId: "implicit_client", ClientName: "client2", ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{"implicit"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client3", ClientId: "hybrid_client", ClientName: "client3", ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{"authorization_code", "implicit"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client4", ClientId: "password_client", ClientName: "client4", ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{"password"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client5", ClientId: "device_code_client", ClientName: "client5", ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{string(constants.DeviceCode)}, RedirectUris: []string{"http://localhost:9000/callback"}},
	})
	router := gin.Default()
	router.LoadHTMLGlob("../static/*.html")
	router.Static("/static", "../static")
	store := memstore.NewStore([]byte("secret"))

	sessionHandler := sessions.Sessions("mysession", store)

	tokenService := impl.NewJwtTokenService(jwt.SigningMethodHS256, []byte("mysecret"), func(token *jwt.Token, userName string, scope string) map[string]interface{} {
		return map[string]interface{}{
			"role": "manager",
		}
	})
	tokenService.TokenLifeTime = config.TokenLifeTime

	authRepo := repo.NewInMemoryAuthorizeRepository()
	consentRepo := repo.NewInMemoryConsentRepository()
	userService := &service.DefaultUserService{
		UserRepository: buildUserRepo(),
	}
	tenant := oauth2.NewTenant(config, clientRepo, authRepo, consentRepo, userService, tokenService, nil)

	tenant.InitOAuth2Router(router, sessionHandler)

	return router, tenant
}
func buildUserRepo() repo.UserRepository {
	pwdHash, _ := utils.HashPassword("password1")
	return repo.NewInMemoryUserRepository([]*model.User{
		{Id: "user1", UserName: "user1", Email: "user1@gmail.com", PasswordHash: pwdHash, Role: "manager"},
		{Id: "user2", UserName: "user2", Email: "user2@gmail.com", PasswordHash: pwdHash},
	})
}
