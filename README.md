# Golang OAuth 2.0 Server Implement IDX-OAUTH2

[![GitHub stars](https://img.shields.io/github/stars/wingfeng/idx-oauth2.svg)](https://github.com/wingfeng/idx-oauth2/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/wingfeng/idx-oauth2.svg)](https://github.com/wingfeng/idx-oauth2/network/members)
[![GitHub issues](https://img.shields.io/github/issues/wingfeng/idx-oauth2.svg)](https://github.com/wingfeng/idx-oauth2/issues)
[![Go Reference](https://pkg.go.dev/badge/github.com/wingfeng/idx-oauth2.svg)](https://pkg.go.dev/github.com/wingfeng/idx-oauth2)
[![ReportCard][reportcard-image]][reportcard-url]
[![License](https://img.shields.io/npm/l/express.svg)](LICENSE)  

## About  

This project is for who want to build your own OAUTH2 and OIDC server with golang,It use for oauth2 to support OIDC and device code grant type. Build your own repository to store users and clients authorizations. the repository provided in this module is just a sample. and it is not recommended to use it in production.  

## Features  
	
OAuth2.0 Server Implementation, Support Grant Types:  

* [Authorization Code Grant Type](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
* [Implicit Grant Type](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-implicit-grant-flow)
* [Resource Owner Password Credentials Grant Type](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc)
* [Client Credentials Grant Type](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
* [Refresh Token Grant Type](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#refresh-the-access-token)
* [Device Code Grant Type](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)  
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

	store := memstore.NewStore([]byte("secret"))

	sessionHandler := sessions.Sessions("mysession", store)
	router.LoadHTMLGlob("../static/*.html")
	router.Static("/img", "../static/img")
	tokenService, jwks := buildTokenService(config)
	clientRepo := buildClientRepo()
	authRepo := repo.NewInMemoryAuthorizeRepository()

	consentRepo := repo.NewInMemoryConsentRepository()

	tenant := oauth2.NewTenant(config, buildUserRepo(), clientRepo, authRepo, consentRepo, tokenService, jwks)

	tenant.InitOAuth2Router(router, sessionHandler)

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

[reportcard-url]: https://goreportcard.com/report/github.com/wingfeng/idx-oauth2
[reportcard-image]: https://goreportcard.com/badge/github.com/wingfeng/idx-oauth2
