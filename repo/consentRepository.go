package repo

type ConsentRepository interface {
	GetConsents(clientId string, principal string) ([]string, error)
	SaveConsents(clientId string, principal string, scopes []string) error
	RemoveConsents(clientId string, principal string) error // remove all consents for clientId and principal
}

type InMemoryConsentRepository struct {
	Consents map[string]map[string][]string
}

func (cr *InMemoryConsentRepository) GetConsents(clientId string, principal string) ([]string, error) {
	return cr.Consents[clientId][principal], nil
}
func (cr *InMemoryConsentRepository) SaveConsents(clientId string, principal string, scopes []string) error {
	if cr.Consents[clientId] == nil {
		cr.Consents[clientId] = make(map[string][]string)
	}
	cr.Consents[clientId][principal] = scopes
	return nil
}
func (cr *InMemoryConsentRepository) RemoveConsents(clientId string, principal string) error {
	delete(cr.Consents[clientId], principal)
	return nil
}
