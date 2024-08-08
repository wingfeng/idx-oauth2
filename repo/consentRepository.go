package repo

import "sync"

type ConsentRepository interface {
	GetConsents(clientId string, principal string) ([]string, error)
	SaveConsents(clientId string, principal string, scopes []string) error
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
