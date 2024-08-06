# Golang OAuth 2.0 Server Implement IDX-OAUTH2

This project is for who want to build your own OAUTH2 and OIDC server with golang,It use for oauth2 to support OIDC and device code grant type. Build your own repository to store usres and clients authorizations. the repository provided in this module is just a sample. and it is not recommended to use it in production.  

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

	router.GET("/logout", endpoint.Logout)
	router.POST("/logout", endpoint.Logout)
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

open your browser with <http://localhost:9000/>