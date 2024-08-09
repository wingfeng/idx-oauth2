# Golang OAuth 2.0 Server Implement IDX-OAUTH2

[![GitHub stars](https://img.shields.io/github/stars/wingfeng/idx-oauth2.svg)](https://github.com/wingfeng/idx-oauth2/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/wingfeng/idx-oauth2.svg)](https://github.com/wingfeng/idx-oauth2/network/members)
[![GitHub issues](https://img.shields.io/github/issues/wingfeng/idx-oauth2.svg)](https://github.com/wingfeng/idx-oauth2/issues)

## About  

This project is for who want to build your own OAUTH2 and OIDC server with golang,It use for oauth2 to support OIDC and device code grant type. Build your own repository to store usres and clients authorizations. the repository provided in this module is just a sample. and it is not recommended to use it in production.  

## Features  
	
OAuth2.0 Server Implementation, Support Grant Types:  

* Authorization Code Grant Type
* Implicit Grant Type
* Resource Owner Password Credentials Grant Type
* Client Credentials Grant Type
* Refresh Token Grant Type
* Password Grant Type
* Device Code Grant Type  
Support OIDC  

## Quick Start  

### 1. Download and Install go module

```cmd
go get -u -v github.com/wingfeng/idx-oauth2
```

### 2. create your main function  

you can find the example in ./example/mainInMem.go

```go
import oauth2 "github.com/wingfeng/idx-oauth2"

func main() {
config := conf.DefaultConfig()
	config.Scheme = "http"

	router := gin.Default()

	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))
	router.Use(endpoint.AuthMiddleware)

	router.Static("/img", "../static/img")
	router.LoadHTMLGlob("../static/*.html")
	router.GET("/", endpoint.Index)
	router.GET("/index.html", endpoint.Index)

	group := router.Group(config.EndpointGroup)

	tokenService, jwks := buildTokenService(config)
	clientRepo := buildClientRepo()
	authRepo := repo.NewInMemoryAuthorizeRepository()

	consentRepo := repo.NewInMemoryConsentRepository()

	tenant := oauth2.NewTenant(config, buildUserRepo(), clientRepo, authRepo, consentRepo, tokenService, jwks)

	tenant.InitOAuth2Router(group, router)

	address := fmt.Sprintf("%s:%d", "", 9097)
	router.Run(address)
	}

```

### 3. test it with the example client  

  you can find the example client in ./example/client/main.go  it is the sample client for oauth2 from <https://github.com/go-oauth2/oauth2>, open another terminal to run followed command  

```cmd
    cd ./example/client
    go run .
```  

Open your browser with <http://localhost:9000/>  

### 4. test it other ways  

* You can also test it with <https://github.com/ECNU/Open-OAuth2Playground> or <https://oauthdebugger.com/debug>  
* Use [Jmeter](https://jmeter.apache.org/) to load the oauth2.jmx file from ./test folder to test this oauth2 server.

[![Go Reference](https://pkg.go.dev/badge/github.com/wingfeng/idx-oauth2.svg)](https://pkg.go.dev/github.com/wingfeng/idx-oauth2) 

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
