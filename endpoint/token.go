package endpoint

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/wingfeng/idx-oauth2/conf"
	constants "github.com/wingfeng/idx-oauth2/const"
	"github.com/wingfeng/idx-oauth2/model"
	"github.com/wingfeng/idx-oauth2/model/request"
	"github.com/wingfeng/idx-oauth2/model/response"
	"github.com/wingfeng/idx-oauth2/service"

	"github.com/gin-gonic/gin"
)

// Url: /token
type TokenController struct {
	AuthorizeService service.AuthorizeService
	ClientService    service.ClientService
	Config           *conf.Config
}

func (ctrl *TokenController) PostToken(ctx *gin.Context) {
	req := &request.TokenRequest{}
	if err := ctx.ShouldBind(req); err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// validate client secret
	// support client_secret_basic token endpoint authentication
	authorizationHeader := ctx.GetHeader("Authorization")
	if !strings.EqualFold(authorizationHeader, "") {
		clientId, clientSecret, ok := ctx.Request.BasicAuth()
		//	slog.Info("Authorization", "Authorization", authorizationHeader, "clientId", clientId, "clientSecret", clientSecret, "ok", ok)
		if ok {
			req.ClientId = clientId
			req.ClientSecret = clientSecret
		}

	}
	if !ctrl.ClientService.ValidateSecret(req.ClientId, req.ClientSecret) {
		ctx.JSON(401, gin.H{"error": "invalid_client or secret"})
		return
	}
	client, err := ctrl.ClientService.GetClient(req.ClientId)
	if err != nil {
		ctx.JSON(401, gin.H{
			"msg":   "invalid client",
			"error": err.Error(),
		})
		return
	}

	if err := ctrl.validateRequest(client, req); err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}
	//set cors headers base on client allow origin

	for _, v := range client.GetWebOrigins() {
		orgin := ctx.Request.Header.Get("Origin")

		if v == "*" || strings.EqualFold(orgin, v) {
			ctx.Header("Access-Control-Allow-Origin", v)
			break
		}
		ctx.Header("Access-Control-Allow-Origin", "null")
	}
	ctx.Header("Access-Control-Request-Method", "GET,POST")

	var authorization *model.Authorization
	switch req.GrantType {
	case string(constants.AuthorizationCode):
		var req request.CodeFlowRequest
		if err := ctx.ShouldBind(&req); err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
		}
		client, err := ctrl.ClientService.GetClient(req.ClientId)
		if err != nil {
			slog.Error("invalid request", "error", "client not found")
			ctx.JSON(400, "invalid request client not found")
		}
		if client.GetRequirePKCE() && req.CodeVerifier == "" {
			slog.Error("invalid request", "error", "code_verifier is required")
			ctx.JSON(400, "invalid request code verifier is required")
		}

		authorization = ctrl.AuthorizeService.GetAuthorizationByCode(req.Code)
		if authorization == nil {
			ctx.JSON(400, gin.H{
				"error": "invalid code",
				"code":  req.Code,
			})
			return
		}
		if len(authorization.CodeChallenge) > 0 {
			switch authorization.CodeChallengeMethod {
			case "S256":
				// Hash the code verifier
				hashedVerifier := sha256.Sum256([]byte(req.CodeVerifier))
				rawEncodedVerifier := base64.RawURLEncoding.EncodeToString(hashedVerifier[:])
				encodedVerifier := base64.URLEncoding.EncodeToString(hashedVerifier[:])
				// Compare the encoded verifier with the stored code challenge
				if !strings.EqualFold(rawEncodedVerifier, authorization.CodeChallenge) && !strings.EqualFold(encodedVerifier, authorization.CodeChallenge) {
					ctx.JSON(400, gin.H{"error": "PKCE error,verifier not match"})
					slog.Error("PKCE not match", "method", "S256", "rawcodeVerifier", rawEncodedVerifier,
						"encodedcodeVerifier", encodedVerifier, "CodeChallenge", authorization.CodeChallenge)
					return
				}
			case "plain":
				if authorization.CodeChallenge != req.CodeVerifier {
					ctx.JSON(400, gin.H{"error": "PKCE error,verifier not match"})
					slog.Error("PKCE not match", "method", "plain", "codeVerifier", req.CodeVerifier, "CodeChallenge", authorization.CodeChallenge)

					return
				}
			}

		}

	case string(constants.PasswordCredentials):
		var req request.PasswordRequest
		if err := ctx.ShouldBind(&req); err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
		}
		//set issuer before create authorization
		req.Issuer = getIssuer(ctx, ctrl.Config)
		authorization, err = ctrl.AuthorizeService.GetAuthorizeionByPassword(&req)
		if err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
			return
		}
	case string(constants.Refreshing):
		var req request.RefreshTokenRequest
		if err := ctx.ShouldBind(&req); err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
			return
		}

		authorization = ctrl.AuthorizeService.GetAuthorizationByRefreshToken(req.RefreshToken)
		if authorization == nil {
			ctx.JSON(400, gin.H{
				"error":        "invalid RefreshToken",
				"RefreshToken": req.RefreshToken,
			})
			return
		}
	case string(constants.DeviceCode):
		var req request.DeviceCodeTokenRequest
		if err := ctx.ShouldBind(&req); err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
			return
		}
		authorization = ctrl.AuthorizeService.GetAuthorizationByDeviceCode(req.DeviceCode)
		if authorization == nil {
			ctx.JSON(400, gin.H{"error": "invalid device code"})
			return
		}
		if strings.EqualFold(authorization.PrincipalName, "") {
			ctx.JSON(400, gin.H{"error": "authorization_pending"})
			return
		}
	default:
		ctx.JSON(400, gin.H{"error": "unsupported_grant_type"})
	}

	if authorization == nil {
		ctx.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}
	// only need to check when flow is authorization code

	response := &response.TokenResponse{}
	response.AccessToken = authorization.AccessToken
	response.RefreshToken = authorization.RefreshToken
	response.TokenType = "Bearer"

	if authorization.IncludeOpenId() {
		response.IDToken = authorization.IDToken
	}

	response.Scope = authorization.Scope

	response.ExpiresIn = authorization.ExpiresAt - time.Now().Unix()
	ctx.JSON(200, response)
}

func (ctrl *TokenController) validateRequest(client model.IClient, req *request.TokenRequest) error {

	if !service.ValidateGrantType(client, req.GrantType) {

		return fmt.Errorf("invalid request,unsupported_grant_type %s", req.GrantType)
	}

	return nil

}
