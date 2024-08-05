package service

import "github.com/wingfeng/idx-oauth2/model"

type TokenService interface {
	GenerateToken(authorization *model.Authorization) (string, error)
	GenerateRefreshToken(authorization *model.Authorization) (string, error)
	GenerateIDToken(authorization *model.Authorization) (string, error)
}

type SampleTokenService struct {
}

func (s *SampleTokenService) GenerateToken(authorization *model.Authorization) (string, error) {
	return "Access Token", nil
}
func (s *SampleTokenService) GenerateRefreshToken(authorization *model.Authorization) (string, error) {
	return "Refresh Token", nil
}
func (s *SampleTokenService) GenerateIDToken(authorization *model.Authorization) (string, error) {
	return "ID Token", nil
}
