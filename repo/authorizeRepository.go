package repo

import (
	"sync"

	"github.com/wingfeng/idx-oauth2/model"
)

// AuthorizationRepository 接口定义了授权操作的相关方法。
type AuthorizationRepository interface {
	// Save 保存授权信息。
	// 参数 authorization: 需要保存的授权信息对象。
	Save(authorization *model.Authorization)

	// Remove 删除指定的授权信息。
	// 参数 authorization: 需要删除的授权信息对象。
	Remove(authorization *model.Authorization)

	// GetAuthorizationByAccessToken 根据访问令牌获取授权信息。
	// 参数 token: 访问令牌。
	// 返回值: 对应的授权信息对象，如果找不到则返回 nil。
	GetAuthorizationByAccessToken(token string) *model.Authorization

	// GetAuthorizationByCode 根据授权码获取授权信息。
	// 参数 code: 授权码。
	// 返回值: 对应的授权信息对象，如果找不到则返回 nil。
	GetAuthorizationByCode(code string) *model.Authorization

	// GetAuthorizationByRefreshToken 根据刷新令牌获取授权信息。
	// 参数 token: 刷新令牌。
	// 返回值: 对应的授权信息对象，如果找不到则返回 nil。
	GetAuthorizationByRefreshToken(token string) *model.Authorization

	// GetAuthorizationByDeviceCode 根据设备码获取授权信息。
	// 参数 device_code: 设备码。
	// 返回值: 对应的授权信息对象，如果找不到则返回 nil。
	GetAuthorizationByDeviceCode(device_code string) *model.Authorization

	// GetAuthorizationByUserCode 根据用户码获取授权信息。
	// 参数 user_code: 用户码。
	// 返回值: 对应的授权信息对象，如果找不到则返回 nil。
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
