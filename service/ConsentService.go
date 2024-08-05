package service

import (
	"log/slog"

	"github.com/wingfeng/idx-oauth2/repo"
)

type ConsentService interface {
	GetConsents(clientId string, principal string) ([]string, error)
	SaveConsents(clientId string, principal string, scopes []string) error
	RemoveConsents(clientId string, principal string) error // remove all consents for clientId and principal
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
