package endpoint

import (
	"log/slog"
	"net/url"
	"strings"

	"github.com/wingfeng/idx-oauth2/conf"
	"github.com/wingfeng/idx-oauth2/model"
	"github.com/wingfeng/idx-oauth2/model/request"
	"github.com/wingfeng/idx-oauth2/service"

	"github.com/gin-gonic/gin"
)

// url: /authorize
// handle get request with query params response_type client_id redirect_uri scope nonc state

type AuthorizeController struct {
	AuthorizeService service.AuthorizeService
	ClientService    service.ClientService
	ConsentSevice    service.ConsentService
	Config           *conf.Config
}

func (ctrl *AuthorizeController) Authorize(ctx *gin.Context) {
	req := &request.AuthorizeRequest{
		ResponseMode:        "query",
		CodeChallengeMethod: "plain", //default PKCE Code Challenge Method plain
	}
	if err := ctx.ShouldBind(req); err != nil {
		slog.Error("invalid request", "error", err)
		ctx.JSON(400, gin.H{
			"error":             "invalid request",
			"error_description": err.Error(),
		})
		return
	}

	client, err := ctrl.ClientService.GetClient(req.ClientId)
	if err != nil || client == nil {
		ctx.JSON(401, gin.H{
			"error":             "invalid Request",
			"error_description": err,
		})
		return
	}
	if client.GetRequirePKCE() && strings.EqualFold(req.CodeChallenge, "") {
		ctx.JSON(400, gin.H{
			"error":             "invalid Request",
			"error_description": "CodeChallenge can't be empty, PKCE Required",
		})
		return
	}
	//verify oauth2.0 authorize request
	//Require code_challenge and code_challenge_method when configed with PKCE
	//handle oauth2 2.0 authorize request
	//validte with client info
	principle := ctx.GetString(Const_Principle)
	//require login when principle is empty
	if strings.EqualFold(principle, "") {
		ShowLogin(ctx, ctx.Request.URL.String(), ctrl.Config)
		return
	}
	slog.Debug("Valide Principle done", "principle", principle)
	if err := ctrl.validateRequest(req); err != nil {
		ctx.JSON(400, gin.H{
			"error":             "invalid request",
			"error_description": err.Error(),
		})
		return
	}
	//verify consent if not popup consent page
	scopes := strings.Split(req.Scope, " ")

	if client.GetRequireConsent() && ctrl.ConsentSevice.RequireConsent(req.ClientId, principle, scopes) {
		ctx.HTML(200, "consent.html", gin.H{
			"client_id":   req.ClientId,
			"client_name": client.GetClientName(),
			"scope":       scopes,
			"tenant":      ctrl.Config.TenantPath,
			"group":       ctrl.Config.EndpointGroup,
			"uri":         ctx.Request.URL.String(),
		})
		return
	}

	req.Issuer = getIssuer(ctx, ctrl.Config)
	authorization := ctrl.AuthorizeService.CreateAuthorization(req, string(principle))

	callbackQuery := make(url.Values)
	if req.ResponseCode() {
		callbackQuery.Add("code", authorization.Code)
	}
	if req.ResponseWithIdToken() {
		callbackQuery.Add("id_token", authorization.IDToken)
	}
	if req.ResponseWithToken() {
		callbackQuery.Add("access_token", authorization.AccessToken)
	}
	callbackQuery.Add("token_type", "Bearer")
	callbackQuery.Add("state", req.State)
	if !strings.EqualFold(req.Nonce, "") {
		callbackQuery.Add("nonce", req.Nonce)
	}

	linkSymbol := "?"
	switch req.ResponseMode {
	case "fragment":
		linkSymbol = "#"
	case "query":
		linkSymbol = "?"
	case "form_post":
		linkSymbol = "#"
	}
	slog.Debug("callback link", "link", req.RedirectUri+linkSymbol+callbackQuery.Encode())
	if req.ResponseMode == "form_post" {
		body := gin.H{
			"callback": req.RedirectUri,
		}
		for key, value := range callbackQuery {
			body[key] = value[0]
		}
		ctx.HTML(200, "form_post.html", body)
		//	http.Post(authorizeRequst.RedirectUri, "application/x-www-form-urlencoded", strings.NewReader(callbackQuery.Encode()))
	} else {
		callbackLink := req.RedirectUri + linkSymbol + callbackQuery.Encode()
		//url.
		ctx.Redirect(302, callbackLink)
	}

}
func (ctrl *AuthorizeController) validateRequest(request *request.AuthorizeRequest) error {

	client := &model.Client{
		ClientId:     request.ClientId,
		ClientScope:  request.Scope,
		RedirectUris: make([]string, 0),
	}
	client.RedirectUris = append(client.RedirectUris, request.RedirectUri)
	client.GrantTypes = service.GetGrantTypeByReponseType(request.ResponseType)

	return ctrl.ClientService.ValidateClient(client)
}
