package service

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/wingfeng/idx-oauth2/model"
	"github.com/wingfeng/idx-oauth2/repo"

	"golang.org/x/crypto/bcrypt"
)

type ClientService interface {
	// GetClient retrieves a client object by the client ID.
	// Parameters:
	//   clientId - The unique identifier of the client.
	// Returns:
	//   model.IClient - An object that implements the client interface.
	//   error - An error message if an error occurs.
	GetClient(clientId string) (model.IClient, error)

	// ValidateSecret verifies whether the client's secret is valid.
	// Parameters:
	//   clientId - The unique identifier of the client.
	//   secret - The client's secret.
	// Returns:
	//   bool - True if the secret is valid, otherwise false.
	ValidateSecret(clientId string, secret string) bool

	// ValidateClient checks if a client object is valid.
	// Parameters:
	//   client - The client object to validate.
	// Returns:
	//   error - An error message if the client object is invalid.
	ValidateClient(client model.IClient) error

	// SetClientRepository sets the client repository.
	// Parameters:
	//   clientRepository - The client repository interface.
	// This method is used for dependency injection to access the client data store when needed.
	SetClientRepository(clientRepository repo.ClientRepository)
	// ValidateLogoutUri validates the logout URI.
	//
	// clientId is the client identifier used to ensure the URI belongs to the correct client.
	// url is the logout URI to validate.
	//
	// The function returns an error if the URI is invalid or unsafe.
	ValidateLogoutUri(clientId string, url string) error
}

type DefaultClientService struct {
	ClientRepository repo.ClientRepository
}

func NewClientService(clientRepository repo.ClientRepository) *DefaultClientService {
	return &DefaultClientService{
		ClientRepository: clientRepository,
	}
}
func (cs *DefaultClientService) SetClientRepository(repo repo.ClientRepository) {
	cs.ClientRepository = repo
}
func (cs *DefaultClientService) GetClient(clientId string) (model.IClient, error) {
	return cs.ClientRepository.GetClientByClientID(clientId)
}
func (cs *DefaultClientService) ValidateSecret(clientId string, secret string) bool {
	client, err := cs.ClientRepository.GetClientByClientID(clientId)
	if client == nil || err != nil {
		slog.Error("Get client error", "error", err)
		return false
	}
	if len(client.GetSecret()) == 0 {
		return true
	}
	secrets := client.GetSecret()
	for _, s := range secrets {
		err = bcrypt.CompareHashAndPassword([]byte(s), []byte(secret))
		if err == nil {
			return true
		}
	}

	return false
}
func (cs *DefaultClientService) ValidateLogoutUri(clientId string, url string) error {
	client, err := cs.ClientRepository.GetClientByClientID(clientId)
	if client == nil || err != nil {
		return fmt.Errorf("client not found %s", clientId)
	}
	uris := client.GetPostLogoutUris()
	for _, uri := range uris {
		if strings.EqualFold(uri, url) {
			return nil
		}
	}
	return fmt.Errorf("invalid post logout url %s", url)
}
func (cs *DefaultClientService) ValidateClient(client model.IClient) error {
	//Validate GrantType
	//Validate Scopes
	//Validate return urls
	if client == nil {
		return errors.New("client can not be nil")
	}
	orgClient, err := cs.ClientRepository.GetClientByClientID(client.GetClientId())

	if err != nil {
		slog.Error("Get client error ", "ClientId", client.GetClientId())
		return fmt.Errorf("get client fail,%s", client.GetClientId())
	}

	if !ValidateScope(orgClient, client.GetScopes()) {
		slog.Error("Invalid scope", "Scope", strings.Join(client.GetScopes(), " "))
		return fmt.Errorf("invalid scope %s", strings.Join(client.GetScopes(), " "))
	}
	for _, gt := range client.GetGrantTypes() {
		if !ValidateGrantType(orgClient, gt) {
			slog.Error("Invalid grant type", "GrantType", gt)
			return fmt.Errorf("invalid grant type %s", gt)
		}
	}
	//there is only on redict Uri in request
	if len(client.GetRedirectUris()) > 0 {
		if !ValidateReturnUri(orgClient, client.GetRedirectUris()[0]) {
			slog.Error("Invalid return url", "ReturnUrl", client.GetRedirectUris()[0])
			return fmt.Errorf("invalid return url %s", client.GetRedirectUris()[0])
		}
	}
	return nil
}
func ValidateScope(client model.IClient, scopes []string) bool {
	scopeValided := true

	for _, scope := range scopes {
		for _, orgScope := range client.GetScopes() {
			if strings.EqualFold(scope, orgScope) {
				scopeValided = true
				break
			}
			scopeValided = false
		}
		if !scopeValided {
			break
		}
	}
	return scopeValided
}
func ValidateGrantType(client model.IClient, grantType string) bool {

	for _, gt := range client.GetGrantTypes() {
		if strings.EqualFold(gt, grantType) {
			return true
		}
	}
	return false
}
func ValidateReturnUri(client model.IClient, uri string) bool {
	supportUris := client.GetRedirectUris()
	for _, supportUri := range supportUris {
		//chang to match with regex
		matched, err := regexp.MatchString(supportUri, uri)
		if err != nil {
			slog.Error("Invalid return url", "ReturnUrl", uri, "Error", err)
			return false
		}
		if matched {
			return true
		}
	}
	return false
}
