package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/wingfeng/idx/oauth2/conf"
	"github.com/wingfeng/idx/oauth2/model"
	"github.com/wingfeng/idx/oauth2/service/impl"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestTokenServiceWithJwks(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	// Convert the RSA public key to PEM format.
	pemPublicKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPEM := pem.EncodeToMemory(pemPublicKey)

	key := conf.NewRSAJWTKeyWithPEM(publicKeyPEM)
	key.Use = "sig"
	key.Kid = "test"
	key.Alg = "RS256"
	jwks := &conf.JWKS{Keys: []interface{}{key}}
	tokenService := impl.NewJwtTokenService(jwt.SigningMethodRS256, privateKey, func(userName string, scope string) map[string]interface{} {
		return map[string]interface{}{"roles": []string{"admin", "manager"}}
	})
	jwksResult, err := json.Marshal(jwks)
	assert.Equal(t, nil, err)
	t.Logf("JWKS:\n %s", jwksResult)
	accessToken, err := tokenService.GenerateIDToken(&model.Authorization{PrincipalName: "sample"})
	assert.Equal(t, nil, err)
	t.Logf("AccessToken:\n %s", accessToken)
}
