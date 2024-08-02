package repo

import (
	"fmt"
	"strings"

	"github.com/wingfeng/idx/oauth2/model"
)

type ClientRepository interface {
	GetClientByClientID(id string) (model.IClient, error)
}

type InMemoryClientRepository struct {
	clients []model.Client
}

func NewInMemoryClientRepository(clients []model.Client) *InMemoryClientRepository {
	return &InMemoryClientRepository{
		clients: clients,
	}
}
func (repo *InMemoryClientRepository) GetClientByClientID(clientId string) (model.IClient, error) {
	for _, client := range repo.clients {
		if strings.EqualFold(client.ClientId, clientId) {
			return &client, nil
		}
	}
	return nil, fmt.Errorf("client not found")
}
