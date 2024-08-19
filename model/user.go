package model

type User struct {
	Id           string `json:"sub"`
	UserName     string `json:"preferred_username"`
	PasswordHash string `json:"-"`
	Email        string `json:"email"`
	Role         string `json:"role"`
}

type IUser interface {
	GetId() string
	GetUserName() string
	GetEmail() string
	GetPasswordHash() string
}

func (u *User) GetId() string {
	return u.Id
}
func (u *User) GetUserName() string {
	return u.UserName
}
func (u *User) GetEmail() string {
	return u.Email
}
func (u *User) GetPasswordHash() string {
	return u.PasswordHash
}
