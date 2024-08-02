package service

import (
	"errors"

	"github.com/wingfeng/idx/oauth2/conf"
	constants "github.com/wingfeng/idx/oauth2/const"

	"log/slog"
	"strings"

	"github.com/wingfeng/idx/oauth2/model"
	"github.com/wingfeng/idx/oauth2/model/request"
	"github.com/wingfeng/idx/oauth2/repo"

	"github.com/google/uuid"
)

type AuthorizeService interface {
	NewId() string
	Save(*model.Authorization)
	Remove(*model.Authorization)
	GetAuthorizationByCode(string) *model.Authorization
	GetAuthorizationByAccessToken(string) *model.Authorization
	GetAuthorizationByRefreshToken(string) *model.Authorization
	GetAuthorizeionByPassword(*request.PasswordRequest) (*model.Authorization, error)
	GetAuthorizationByDeviceCode(device_code string) *model.Authorization
	GetAuthorizationByUserCode(user_code string) *model.Authorization
	GenerateDeviceAuthorization(clientId string, scope string) *model.Authorization
	CreateAuthorization(request *request.AuthorizeRequest, principal string) *model.Authorization
	GenerateUserCode() string
	GenerateDeviceCode() string
}

type DefaultAuthorizeService struct {
	repo          repo.AuthorizationRepository
	TokenService  TokenService
	UserService   UserService
	ClientService ClientService
	Config        *conf.Config
}

func (srv *DefaultAuthorizeService) NewId() string {
	return uuid.New().String()
}
func (srv *DefaultAuthorizeService) Save(auth *model.Authorization) {
	srv.repo.Save(auth)
}
func (srv *DefaultAuthorizeService) Remove(auth *model.Authorization) {
	srv.repo.Remove(auth)
}
func (srv *DefaultAuthorizeService) GetAuthorizationByCode(code string) *model.Authorization {

	return srv.repo.GetAuthorizationByCode(code)
}
func (srv *DefaultAuthorizeService) GetAuthorizationByAccessToken(token string) *model.Authorization {

	return srv.repo.GetAuthorizationByAccessToken(token)
}
func (srv *DefaultAuthorizeService) GetAuthorizationByRefreshToken(token string) *model.Authorization {
	//Todo: regenerate token
	auth := srv.repo.GetAuthorizationByRefreshToken(token)
	if auth != nil {
		auth.UpdateExiresIn(int64(srv.Config.TokenLifeTime))
		auth.AccessToken, _ = srv.TokenService.GenerateToken(auth)
		auth.RefreshToken, _ = srv.TokenService.GenerateRefreshToken(auth)
		auth.IDToken, _ = srv.TokenService.GenerateIDToken(auth)
	}
	srv.Save(auth)
	return auth

}
func (src *DefaultAuthorizeService) CreateAuthorization(request *request.AuthorizeRequest, principal string) *model.Authorization {
	code := uuid.New().String()
	user, err := src.UserService.GetUserByName(principal)
	if err != nil {
		slog.Error("get user by name error", "error", err, "UserName", principal)
	}
	auth := &model.Authorization{
		Id:                  src.NewId(),
		ClientId:            request.ClientId,
		GrantType:           string(constants.AuthorizationCode),
		PrincipalName:       principal,
		Subject:             user.GetId(),
		Scope:               request.Scope,
		Code:                code,
		Nonce:               request.Nonce,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
	}

	auth.UpdateExiresIn(src.Config.TokenLifeTime)
	auth.GrantType = strings.Join(GetGrantTypeByReponseType(request.ResponseType), " ")
	accessToken, err := src.TokenService.GenerateToken(auth)
	if err != nil {
		slog.Error("generate access token error", "error", err)
	}
	auth.AccessToken = accessToken

	refeshToken, err := src.TokenService.GenerateRefreshToken(auth)
	if err != nil {
		slog.Error("generate refresh token error", "error", err)
	}
	auth.RefreshToken = refeshToken
	idToken, err := src.TokenService.GenerateIDToken(auth)
	if err != nil {
		slog.Error("generate id token error", "error", err)
	}
	auth.IDToken = idToken
	src.Save(auth)
	return auth
}
func (srv *DefaultAuthorizeService) GetAuthorizeionByPassword(request *request.PasswordRequest) (*model.Authorization, error) {
	clientId, userName, password := request.ClientId, request.UserName, request.Password
	if !srv.UserService.VerifyPassword(userName, password) {
		return nil, errors.New("invalid user name or password")
	}
	user, err := srv.UserService.GetUserByName(userName)
	if err != nil {
		return nil, err
	}
	auth := &model.Authorization{
		Id:            srv.NewId(),
		ClientId:      clientId,
		GrantType:     string(constants.PasswordCredentials),
		Scope:         request.Scope,
		PrincipalName: userName,
		Subject:       user.GetId(),
	}
	auth.UpdateExiresIn(int64(srv.Config.TokenLifeTime))
	auth.AccessToken, _ = srv.TokenService.GenerateToken(auth)
	auth.RefreshToken, _ = srv.TokenService.GenerateRefreshToken(auth)
	auth.IDToken, _ = srv.TokenService.GenerateIDToken(auth)
	//save authorize to repo
	srv.Save(auth)
	return auth, nil

}
func (srv *DefaultAuthorizeService) GetAuthorizationByDeviceCode(device_code string) *model.Authorization {
	auth := srv.repo.GetAuthorizationByDeviceCode(device_code)
	if auth == nil || strings.EqualFold(auth.PrincipalName, "") {
		return auth
	}
	user, err := srv.UserService.GetUserByName(auth.PrincipalName)
	if err != nil {
		slog.Error("get user by name error", "error", err, "UserName", auth.PrincipalName)
	}

	auth.Subject = user.GetId()

	if strings.EqualFold(auth.AccessToken, "") {
		auth.AccessToken, _ = srv.TokenService.GenerateToken(auth)
		auth.RefreshToken, _ = srv.TokenService.GenerateRefreshToken(auth)
		if auth.IncludeOpenId() {
			auth.IDToken, _ = srv.TokenService.GenerateIDToken(auth)
		}

	}
	srv.repo.Save(auth)
	return auth
}
func (srv *DefaultAuthorizeService) GetAuthorizationByUserCode(user_code string) *model.Authorization {
	return srv.repo.GetAuthorizationByUserCode(user_code)
}
func (srv *DefaultAuthorizeService) GenerateDeviceAuthorization(clientId string, scope string) *model.Authorization {
	auth := &model.Authorization{
		Id:         srv.NewId(),
		ClientId:   clientId,
		GrantType:  string(constants.DeviceCode),
		Scope:      scope,
		UserCode:   srv.GenerateUserCode(),
		DeviceCode: srv.GenerateDeviceCode(),
	}
	auth.UpdateExiresIn(int64(srv.Config.DeviceCodeLifeTime))
	//save authorize to repo
	srv.Save(auth)
	return auth

}
func GetGrantTypeByReponseType(responseType string) []string {
	tmp := strings.Split(responseType, " ")
	result := make([]string, 0)
	for _, response := range tmp {
		response = strings.ToLower(response)
		switch response {
		case "code":
			result = append(result, string(constants.AuthorizationCode))
		case "token", "id_token":
			result = append(result, string(constants.Implicit))

		}
	}
	return result
}
func (srv *DefaultAuthorizeService) GenerateUserCode() string {
	//generate user code with 8 digit random characters
	return uuid.New().String()
}
func (srv *DefaultAuthorizeService) GenerateDeviceCode() string {
	return uuid.New().String()
}
func NewAuthorizeService(ts TokenService, config *conf.Config, repo repo.AuthorizationRepository, userService UserService) *DefaultAuthorizeService {
	return &DefaultAuthorizeService{
		repo:         repo,
		TokenService: ts,
		Config:       config,
		UserService:  userService,
	}
}
