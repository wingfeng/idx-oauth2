package repo

import (
	"fmt"
	"strings"

	"github.com/wingfeng/idx-oauth2/model"
)

// ClientRepository 定义了用于操作客户端数据的接口。
type ClientRepository interface {
	// GetClientByClientID 通过客户端ID获取客户端信息。
	// 参数 id: 客户端的唯一标识符。
	// 返回值:
	// - model.IClient: 客户端信息，如果找到则返回实例，否则为nil。
	// - error: 如果操作失败则返回错误信息，否则为nil。
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
