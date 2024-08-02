package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/wingfeng/idx/oauth2/conf"
	constants "github.com/wingfeng/idx/oauth2/const"
	"github.com/wingfeng/idx/oauth2/core"
	"github.com/wingfeng/idx/oauth2/endpoint"
	"github.com/wingfeng/idx/oauth2/model"
	"github.com/wingfeng/idx/oauth2/repo"
	"github.com/wingfeng/idx/oauth2/service"
	"github.com/wingfeng/idx/oauth2/service/impl"
	"github.com/wingfeng/idx/oauth2/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

func main() {
	logLevel := slog.LevelDebug
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})

	slog.SetDefault(slog.New(handler))
	config := conf.DefaultConfig()
	config.Scheme = "http"

	clientRepo := buildClientRepo()
	router := gin.Default()
	router.Use(func(ctx *gin.Context) {
		principle := ""

		cookie, err := ctx.Request.Cookie(endpoint.Const_Principle)
		if err == nil {
			principle = cookie.Value
			slog.Info("User logged in ", "user", principle)
			ctx.Set(endpoint.Const_Principle, cookie.Value)
		}
		ignorePaths := []string{"/login", "/oauth2/token", "/oauth2/authorize", "/oauth2/device",
			"/.well-known/openid-configuration",
			"/.well-known/jwks",
		}
		for _, ignorePath := range ignorePaths {
			if ctx.Request.URL.Path == ignorePath {
				ctx.Next()
				return
			}
		}

		if strings.EqualFold(principle, "") {

			link := ctx.Request.URL.String()
			slog.Info("Principle empty begin redirect", "principle", principle, "link", link)
			ctx.HTML(401, "login.html", gin.H{
				"redirect": link,
			})

			return
		}

		ctx.Next()
	})
	router.Static("/img", "./static/img")
	router.LoadHTMLGlob("./static/*.html")
	router.GET("/", endpoint.Index)
	router.GET("/index.html", endpoint.Index)

	router.GET("/logout", endpoint.Logout)
	router.POST("/logout", endpoint.Logout)
	group := router.Group("/oauth2")

	tokenService, jwks := buildTokenService(config)

	authRepo := repo.NewInMemoryAuthorizeRepository()

	consentRepo := &repo.InMemoryConsentRepository{
		Consents: make(map[string]map[string][]string),
	}

	tenant := core.NewTenant(config, buildUserRepo(), clientRepo, authRepo, consentRepo, tokenService, jwks)

	tenant.InitOAuth2Router(group, router)

	address := fmt.Sprintf("%s:%d", "", 9097)
	router.Run(address)
}

func buildClientRepo() *repo.InMemoryClientRepository {
	secret, _ := utils.HashPassword("secret")
	clientRepo := repo.NewInMemoryClientRepository([]model.Client{
		{Id: "client1", ClientId: "code_client", ClientName: "client1", RequireConsent: true, ClientScope: "openid email profile ", Secret: "", GrantTypes: []string{"authorization_code", "refresh_token", "password"}, RedirectUris: []string{"http://localhost:9000/callback", "https://oauthdebugger.com/debug"}},
		{Id: "client2", ClientId: "implicit_client", ClientName: "client2", RequireConsent: true, ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{"implicit"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client3", ClientId: "hybrid_client", ClientName: "client3", RequireConsent: true, ClientScope: "openid email profile ", Secret: "", GrantTypes: []string{"authorization_code", "implicit"}, RedirectUris: []string{"http://localhost:9000/callback", "https://oauthdebugger.com/debug"}},
		{Id: "client4", ClientId: "password_client", ClientName: "client4", RequireConsent: true, ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{"password"}, RedirectUris: []string{"http://localhost:9000/callback"}},
		{Id: "client5", ClientId: "device_code_client", ClientName: "client5", RequireConsent: true, ClientScope: "openid email profile ", Secret: secret, GrantTypes: []string{string(constants.DeviceCode)}, RedirectUris: []string{"http://localhost:9000/callback"}},
	})
	return clientRepo
}
func buildUserRepo() repo.UserRepository {
	pwdHash, _ := utils.HashPassword("password1")
	return repo.NewInMemoryUserRepository([]*model.User{
		{Id: "user1", UserName: "user1", Email: "user1@gmail.com", PasswordHash: pwdHash},
		{Id: "user2", UserName: "user2", Email: "user2@gmail.com", PasswordHash: pwdHash},
	})
}
func buildTokenService(config *conf.Config) (service.TokenService, *conf.JWKS) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	// Convert the RSA public key to PEM format.
	pemPublicKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPEM := pem.EncodeToMemory(pemPublicKey)

	key := conf.NewRSAJWTKeyWithPEM(publicKeyPEM)
	key.Use = "sig"
	key.Kid = uuid.NewString()
	key.Alg = "RS256"
	jwks := &conf.JWKS{Keys: []interface{}{key}}
	tokenService := impl.NewJwtTokenService(jwt.SigningMethodRS256, privateKey, func(userName string, scope string) map[string]interface{} {
		return map[string]interface{}{"roles": []string{"admin", "manager"}}
	})

	tokenService.TokenLifeTime = config.TokenLifeTime

	return tokenService, jwks
}
