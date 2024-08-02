package service

import (
	"log/slog"

	"github.com/wingfeng/idx/oauth2/model"
	"github.com/wingfeng/idx/oauth2/repo"

	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	GetUser(userId string) (model.IUser, error)
	GetUserByName(userName string) (model.IUser, error)
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
	user, err := us.UserRepository.GetUserByName(userName)
	if err != nil || user == nil {
		slog.Error("VerifyPassword error", "error", err, "user name", userName)
		return false
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.GetPasswordHash()), []byte(password))
	return err == nil

}
