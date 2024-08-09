package repo

import "sync"

// ConsentRepository defines the interface for consent operations, providing methods for querying, saving, and removing consents.
type ConsentRepository interface {
	// GetConsents retrieves all consents for a given client and principal.
	// Parameters:
	//   clientId - the unique identifier of the client application.
	//   principal - the identifier of the consent-granting user.
	// Returns:
	//   A list of consents and an error, if any occurs during retrieval.
	GetConsents(clientId string, principal string) ([]string, error)

	// SaveConsents saves the consents for a given client, principal, and scopes.
	// Parameters:
	//   clientId - the unique identifier of the client application.
	//   principal - the identifier of the consent-granting user.
	//   scopes - a list of scopes the user has consented to.
	// Returns an error if saving fails.
	SaveConsents(clientId string, principal string, scopes []string) error

	// RemoveConsents removes all consents for a given client and principal.
	// Parameters:
	//   clientId - the unique identifier of the client application.
	//   principal - the identifier of the consent-granting user.
	// Returns an error if removal fails.
	RemoveConsents(clientId string, principal string) error // remove all consents for clientId and principal
}

type InMemoryConsentRepository struct {
	lock     *sync.RWMutex
	Consents map[string]map[string][]string
}

func NewInMemoryConsentRepository() *InMemoryConsentRepository {
	return &InMemoryConsentRepository{Consents: make(map[string]map[string][]string),
		lock: &sync.RWMutex{},
	}
}
func (cr *InMemoryConsentRepository) GetConsents(clientId string, principal string) ([]string, error) {
	cr.lock.RLock()
	defer cr.lock.RUnlock()
	return cr.Consents[clientId][principal], nil
}
func (cr *InMemoryConsentRepository) SaveConsents(clientId string, principal string, scopes []string) error {
	cr.lock.Lock()
	defer cr.lock.Unlock()
	if cr.Consents[clientId] == nil {
		cr.Consents[clientId] = make(map[string][]string)
	}
	cr.Consents[clientId][principal] = scopes
	return nil
}
func (cr *InMemoryConsentRepository) RemoveConsents(clientId string, principal string) error {
	cr.lock.Lock()
	defer cr.lock.Unlock()
	delete(cr.Consents[clientId], principal)
	return nil
}
