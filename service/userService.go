package service

import (
	"log/slog"

	"github.com/wingfeng/idx-oauth2/model"
	"github.com/wingfeng/idx-oauth2/repo"

	"golang.org/x/crypto/bcrypt"
)

// UserService defines the interface for user service, including user retrieval and password verification functionalities.
type UserService interface {
	// GetUser retrieves user information by user ID.
	// Parameters:
	//   userId: The user's ID.
	// Returns:
	//   IUser: User information interface.
	//   error: An error if the operation fails.
	GetUser(userId string) (model.IUser, error)

	// GetUserByName retrieves user information by username.
	// Parameters:
	//   userName: The username.
	// Returns:
	//   IUser: User information interface.
	//   error: An error if the operation fails.
	GetUserByName(userName string) (model.IUser, error)

	// VerifyPassword checks whether the provided username and password match.
	// Parameters:
	//   userName: The username.
	//   password: The password.
	// Returns:
	//   bool: True if the password matches, false otherwise.
	VerifyPassword(userName string, password string) bool
}

type DefaultUserService struct {
	UserRepository repo.UserRepository
}

func (us *DefaultUserService) GetUser(userId string) (model.IUser, error) {
	return us.UserRepository.GetUser(userId)
}
func (us *DefaultUserService) GetUserByName(userName string) (model.IUser, error) {
	return us.UserRepository.GetUserByName(userName)
}
func (us *DefaultUserService) VerifyPassword(userName string, password string) bool {
	pwdHash, err := us.UserRepository.GetUserPasswordHash(userName)
	if err != nil {
		slog.Error("VerifyPassword error", "error", err, "user name", userName)
		return false
	}
	err = bcrypt.CompareHashAndPassword([]byte(pwdHash), []byte(password))
	return err == nil

}
