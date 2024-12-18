package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/gin-contrib/sessions"
	gormsessions "github.com/gin-contrib/sessions/gorm"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	idxgorm "github.com/wingfeng/idx-gorm"
	"github.com/wingfeng/idx-gorm/models"
	"github.com/wingfeng/idx-gorm/repo"
	oauth2 "github.com/wingfeng/idx-oauth2"

	"github.com/wingfeng/idx-oauth2/conf"

	"github.com/wingfeng/idx-oauth2/service"
	"github.com/wingfeng/idx-oauth2/service/impl"
)

func main() {

	log := *flag.String("log", "debug", "Log Level")
	dbDriver := *flag.String("db", "pgx", "DB Driver:mysql,pgx")
	dbConnection := *flag.String("dbConnection", "host=localhost port=5432 user=root password=pass@word1 dbname=idx sslmode=disable TimeZone=Asia/Shanghai", "DB Connection")
	port := *flag.Int("port", 9097, "Server Port")
	flag.Parse()

	//配置Log
	logLevel := slog.LevelWarn
	switch strings.ToLower(log) {
	case "debug":
		logLevel = slog.LevelDebug

	case "info":
		logLevel = slog.LevelInfo

	case "warn":
		logLevel = slog.LevelWarn

	}
	slog.Info("Set Log Level", "Level", logLevel)
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(handler))

	config := conf.DefaultConfig()

	//初始化DB
	db := idxgorm.GetDB(dbDriver, dbConnection)

	router := gin.Default()
	store := gormsessions.NewStore(db, true, []byte("secret"))

	authRepo := repo.NewAuthorizationRepository(db)
	userRepo := repo.NewUserRepository(db)
	consentRepo := repo.NewConsentRepository(db)
	clientRepo := repo.NewClientRepository(db)
	tokenService, jwks := buildTokenService(config, userRepo)
	userService := &service.DefaultUserService{
		UserRepository: userRepo,
	}
	tenant := oauth2.NewTenant(config, clientRepo, authRepo, consentRepo, userService, tokenService, jwks)

	tenant.InitOAuth2Router(router, sessions.Sessions("mysession", store))

	router.Static("/img", "../../static/img")
	router.LoadHTMLGlob("../../static/*.html")

	slog.Info("Server is running at", "port", port)

	address := fmt.Sprintf("%s:%d", "", port)
	//l := logger{}
	//	router.RunTLS(address, "../certs/ca/localhost/localhost.crt", "../certs/ca/localhost/localhost.key")
	err := router.Run(address)
	//err = http.ListenAndServe(address, handler) //accesslog.NewLoggingHandler(handler, l))
	if err != nil {
		slog.Error("Server Error", "error", err)
	}

}

func buildTokenService(config *conf.Config, userRepo *repo.DBUserRepository) (service.TokenService, *conf.JWKS) {
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
	key.Kid = "d2a820a8916647f7ac72627ec0ae4f94"
	key.Alg = "RS256"
	jwks := &conf.JWKS{Keys: []interface{}{key}}

	tokenService := impl.NewJwtTokenService(jwt.SigningMethodRS256, privateKey, func(token *jwt.Token, userName string, scope string) map[string]interface{} {
		u, _ := userRepo.GetUserByName(userName)
		user := u.(*models.User)
		result := map[string]interface{}{}
		token.Header["kid"] = key.Kid
		//
		if strings.Contains(scope, "mobile") {
			result["mobile"] = user.PhoneNumber
		}
		if strings.Contains(scope, "email") {
			result["email"] = user.GetEmail()
		}
		return result
	})

	tokenService.TokenLifeTime = config.TokenLifeTime

	return tokenService, jwks
}
