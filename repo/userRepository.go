package repo

import "github.com/wingfeng/idx/oauth2/model"

type UserRepository interface {
	GetUser(userId string) (model.IUser, error)
	GetUserByName(userName string) (model.IUser, error)
}

type InMemoryUserRepository struct {
	users map[string]*model.User
}

func NewInMemoryUserRepository(users []*model.User) *InMemoryUserRepository {
	result := &InMemoryUserRepository{
		users: make(map[string]*model.User),
	}
	for _, user := range users {
		result.users[user.Id] = user
	}
	return result
}

func (ir *InMemoryUserRepository) GetUser(userId string) (model.IUser, error) {
	return ir.users[userId], nil
}
func (ir *InMemoryUserRepository) GetUserByName(userName string) (model.IUser, error) {
	for _, user := range ir.users {
		if user.UserName == userName {
			return user, nil
		}
	}
	return nil, nil
}
