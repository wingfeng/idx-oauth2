package repo

import (
	"sync"

	"github.com/wingfeng/idx-oauth2/model"
)

type AuthorizationRepository interface {
	Save(authorization *model.Authorization)
	Remove(authorization *model.Authorization)
	GetAuthorizationByAccessToken(token string) *model.Authorization
	GetAuthorizationByCode(code string) *model.Authorization
	GetAuthorizationByRefreshToken(token string) *model.Authorization
	GetAuthorizationByDeviceCode(device_code string) *model.Authorization
	GetAuthorizationByUserCode(user_code string) *model.Authorization
}

type InMemoryAuthorizeRepository struct {
	lock           sync.RWMutex
	Authorizations map[string]*model.Authorization
}

func NewInMemoryAuthorizeRepository() *InMemoryAuthorizeRepository {
	return &InMemoryAuthorizeRepository{
		lock:           sync.RWMutex{},
		Authorizations: make(map[string]*model.Authorization),
	}
}
func (repo *InMemoryAuthorizeRepository) Save(authorization *model.Authorization) {
	repo.lock.Lock()
	defer repo.lock.Unlock()
	repo.Authorizations[authorization.Id] = authorization
}
func (repo *InMemoryAuthorizeRepository) Remove(authorization *model.Authorization) {
	repo.lock.Lock()
	defer repo.lock.Unlock()
	delete(repo.Authorizations, authorization.Id)
}
func (repo *InMemoryAuthorizeRepository) GetAuthorizationByAccessToken(token string) *model.Authorization {
	repo.lock.RLock()
	defer repo.lock.RUnlock()

	for _, authorization := range repo.Authorizations {
		if authorization.AccessToken == token {
			return authorization
		}
	}
	return nil
}
func (repo *InMemoryAuthorizeRepository) GetAuthorizationByCode(code string) *model.Authorization {
	repo.lock.RLock()
	defer repo.lock.RUnlock()
	for _, authorization := range repo.Authorizations {
		if authorization.Code == code {
			return authorization
		}
	}
	return nil
}
func (repo *InMemoryAuthorizeRepository) GetAuthorizationByRefreshToken(token string) *model.Authorization {
	repo.lock.RLock()
	defer repo.lock.RUnlock()
	for _, authorization := range repo.Authorizations {
		if authorization.RefreshToken == token {
			return authorization
		}
	}
	return nil
}
func (repo *InMemoryAuthorizeRepository) GetAuthorizationByDeviceCode(device_code string) *model.Authorization {
	repo.lock.RLock()
	defer repo.lock.RUnlock()
	for _, authorization := range repo.Authorizations {
		if authorization.DeviceCode == device_code {
			return authorization
		}
	}
	return nil
}
func (repo *InMemoryAuthorizeRepository) GetAuthorizationByUserCode(user_code string) *model.Authorization {
	repo.lock.RLock()
	defer repo.lock.RUnlock()
	for _, authorization := range repo.Authorizations {
		if authorization.UserCode == user_code {
			return authorization
		}
	}
	return nil
}
