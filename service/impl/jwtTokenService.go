package impl

import (
	"log/slog"
	"time"

	"github.com/wingfeng/idx/oauth2/model"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type JWTTokenService struct {
	Method        jwt.SigningMethod
	SignKey       interface{}
	TokenLifeTime int64
	//use for add addition claims to idtoken base on scope required
	AddClaims func(userName string, scope string) map[string]interface{}
}

func NewJwtTokenService(method jwt.SigningMethod, signKey interface{}, getClaims func(userName string, scope string) map[string]interface{}) *JWTTokenService {
	return &JWTTokenService{
		Method:    method,
		SignKey:   signKey,
		AddClaims: getClaims,
	}
}

func (s *JWTTokenService) GenerateToken(authorization *model.Authorization) (string, error) {
	userName := authorization.PrincipalName
	token := jwt.NewWithClaims(s.Method, jwt.MapClaims{
		"sub":   authorization.Subject, // subject
		"name":  userName,
		"iat":   time.Now().Unix(),       // issued at
		"exp":   authorization.ExpiresAt, // expires at
		"aud":   authorization.ClientId,
		"nonce": authorization.Nonce,
	})

	//do not add additional claims to access token. only added to id token
	// if s.GetClaims != nil {
	// 	claims := s.GetClaims(userName)
	// 	for k, v := range claims {
	// 		token.Claims.(jwt.MapClaims)[k] = v
	// 	}
	// }
	tokenString, err := token.SignedString(s.SignKey)
	if err != nil {
		slog.Error("Token Sign Error")
	}
	return tokenString, nil
	//generate a token
}
func (s *JWTTokenService) GenerateRefreshToken(authorization *model.Authorization) (string, error) {
	return uuid.NewString(), nil
}
func (s *JWTTokenService) GenerateIDToken(authorization *model.Authorization) (string, error) {
	userName := authorization.PrincipalName
	token := jwt.NewWithClaims(s.Method, jwt.MapClaims{
		"sub":  authorization.Subject, // subject
		"name": userName,
		"iat":  time.Now().Unix(),       // issued at
		"exp":  authorization.ExpiresAt, // expires at
	})
	if s.AddClaims != nil {
		claims := s.AddClaims(userName, authorization.Scope)
		for k, v := range claims {
			token.Claims.(jwt.MapClaims)[k] = v
		}
	}
	tokenString, err := token.SignedString(s.SignKey)
	if err != nil {
		slog.Error("Token Sign Error")
	}
	return tokenString, nil
}
