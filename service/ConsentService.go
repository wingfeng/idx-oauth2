package service

import (
	"log/slog"

	"github.com/wingfeng/idx-oauth2/repo"
)

// ConsentService defines the interface for handling user consents.
// It provides operations for querying, saving, removing, and checking consents.
type ConsentService interface {
	// GetConsents retrieves all consents for a given client and principal.
	// Parameters:
	//   clientId - the unique identifier of the client application.
	//   principal - the identifier of the consent principal, usually the user ID.
	// Returns:
	//   A list of consents (scopes) agreed to by the principal for the client application.
	//   An error, if any occurs during the retrieval process.
	GetConsents(clientId string, principal string) ([]string, error)

	// SaveConsents saves new consents for a given client and principal.
	// Parameters:
	//   clientId - the unique identifier of the client application.
	//   principal - the identifier of the consent principal, usually the user ID.
	//   scopes - a list of scopes (consent items) to be saved.
	// Returns:
	//   An error, if any occurs during the saving process.
	SaveConsents(clientId string, principal string, scopes []string) error

	// RemoveConsents removes all consents for a given client and principal.
	// Parameters:
	//   clientId - the unique identifier of the client application.
	//   principal - the identifier of the consent principal, usually the user ID.
	// Returns:
	//   An error, if any occurs during the removal process.
	RemoveConsents(clientId string, principal string) error

	// RequireConsent checks if a given client and principal require consent for specific scopes.
	// Parameters:
	//   clientId - the unique identifier of the client application.
	//   principal - the identifier of the consent principal, usually the user ID.
	//   scopes - a list of scopes (consent items) to be checked.
	// Returns:
	//   true if the principal needs to provide consent for the specified scopes under the client application; otherwise, false.
	RequireConsent(clientId string, principal string, scopes []string) bool
}

// func NewConsentService() ConsentService {

// }

type DefaultConsentService struct {
	Repo repo.ConsentRepository
}

func (cc *DefaultConsentService) GetConsents(clientId string, principal string) ([]string, error) {
	return cc.Repo.GetConsents(clientId, principal)
}
func (cc *DefaultConsentService) SaveConsents(clientId string, principal string, scopes []string) error {

	return cc.Repo.SaveConsents(clientId, principal, scopes)
}
func (cc *DefaultConsentService) RemoveConsents(clientId string, principal string) error {
	cc.Repo.RemoveConsents(clientId, principal)
	return nil
}

// need to popup the consent page or not
func (cc *DefaultConsentService) RequireConsent(clientId string, principal string, scopes []string) bool {
	savedScopes, err := cc.GetConsents(clientId, principal)
	if err != nil {
		slog.Error("get consents error", "err", err)
		return true
	}
	//make sure all scopes are not matched
	// 将savedScopes转换为map，以O(1)复杂度检查元素是否存在
	savedScopesMap := make(map[string]bool)
	for _, scope := range savedScopes {
		savedScopesMap[scope] = true
	}

	// 遍历scopes，如果发现任何scope不在savedScopesMap中，则立即返回true
	for _, scope := range scopes {
		if !savedScopesMap[scope] {
			return true
		}
	}

	// 所有scopes都不在savedScopes中
	return false
}
