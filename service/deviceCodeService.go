package service

import "github.com/wingfeng/idx/oauth2/model/response"

type DeviceCodeService interface {
	GenerateDeviceCode(clientId string, principal string, scopes []string) (*response.DeviceCodeResponse, error)
}
