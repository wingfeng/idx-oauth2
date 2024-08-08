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
func main() {
    // create a gin router
    router := gin.Default()
    // create a session store
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))
    // set a middleware to get the principle from session
	router.Use(func(ctx *gin.Context) {
		principle := ""
		session := sessions.Default(ctx)
		v := session.Get(endpoint.Const_Principle)
		if v != nil {
			principle = v.(string)
		}
		if !strings.EqualFold(principle, "") {
			ctx.Set(endpoint.Const_Principle, principle)
		}
		slog.Info("User logged in ", "user", principle)

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
    // load static and template files
	router.Static("/img", "../static/img")
	router.LoadHTMLGlob("../static/*.html")

	router.GET("/", endpoint.Index)
	router.GET("/index.html", endpoint.Index)


	group := router.Group("/oauth2")
    // build your own token service
	tokenService, jwks := buildTokenService(config)
    // build your own  repositories
	clientRepo := buildClientRepo()
	authRepo := repo.NewInMemoryAuthorizeRepository()

	consentRepo := &repo.InMemoryConsentRepository{
		Consents: make(map[string]map[string][]string),
	}
    // build your own tenant
	tenant := core.NewTenant(config, buildUserRepo(), clientRepo, authRepo, consentRepo, tokenService, jwks)
    // Init oauth2 router    
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

### 4. test it with the example client  

* Open your browser with <http://localhost:9000/>  
* You can also test it with <https://github.com/ECNU/Open-OAuth2Playground> or <https://oauthdebugger.com/debug>  
* Use [Jmeter](https://jmeter.apache.org/) to load the oauth2.jmx file from ./test folder to test this oauth2 server.

[![Go Reference](https://pkg.go.dev/badge/github.com/wingfeng/idx-oauth2.svg)](https://pkg.go.dev/github.com/wingfeng/idx-oauth2) 

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
