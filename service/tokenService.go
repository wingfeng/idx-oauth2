package service

import "github.com/wingfeng/idx-oauth2/model"

// TokenService defines the service interface for token generation.
// This interface includes three methods for generating different types of tokens.
type TokenService interface {
	// GenerateToken generates an access token based on the authorization information.
	// Parameters:
	// - authorization: An object containing user authorization details.
	// Returns:
	// - string: The generated access token.
	// - error: If there is an error during token generation, returns the error.
	GenerateToken(authorization *model.Authorization) (string, error)

	// GenerateRefreshToken generates a refresh token based on the authorization information.
	// Parameters:
	// - authorization: An object containing user authorization details.
	// Returns:
	// - string: The generated refresh token.
	// - error: If there is an error during token generation, returns the error.
	GenerateRefreshToken(authorization *model.Authorization) (string, error)

	// GenerateIDToken generates an identity token based on the authorization information.
	// Parameters:
	// - authorization: An object containing user authorization details.
	// Returns:
	// - string: The generated identity token.
	// - error: If there is an error during token generation, returns the error.
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
