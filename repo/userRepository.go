package repo

import "github.com/wingfeng/idx-oauth2/model"

// UserRepository defines the interface for user data operations.
type UserRepository interface {
	// GetUser retrieves user information by user ID.
	// Parameters:
	//   userId - The unique identifier of the user.
	// Returns:
	//   IUser interface, representing user information.
	//   error - An error message, if the operation fails.
	GetUser(userId string) (model.IUser, error)

	// GetUserByName retrieves user information by username.
	// Parameters:
	//   userName - The username.
	// Returns:
	//   IUser interface, representing user information.
	//   error - An error message, if the operation fails.
	GetUserByName(userName string) (model.IUser, error)
	// GetUserPasswordHash retrieves the password hash for a user.
	// Parameters:
	//   username - The username.
	// Returns:
	//   string, representing the password hash.
	//   error - An error message, if the operation fails.
	GetUserPasswordHash(username string) (string, error)
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
func (ir *InMemoryUserRepository) GetUserPasswordHash(userName string) (string, error) {
	for _, user := range ir.users {
		if user.UserName == userName {
			return user.PasswordHash, nil
		}
	}
	return "", nil
}
