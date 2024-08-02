package conf

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"log/slog"
)

type JWKS struct {
	Keys []interface{} `json:"keys"`
}
type JWTKey struct {
	KeyType string `json:"kty"`
	Use     string `json:"use"`
	Kid     string `json:"kid"`
	//	X5t string `json:"x5t"`
	//	E   string `json:"e"`
	//	N   string `json:"n"`
	//	X5c string `json:"x5c"`
	Alg string `json:"alg"`
}

type RSAJWTKey struct {
	JWTKey
	E         string         `json:"e"` //The "e" (exponent) parameter contains the exponent value for the RSA	public key.
	N         string         `json:"n"` //The "n" (modulus) parameter contains the modulus value for the RSA public key.  It is represented as a Base64urlUInt-encoded value.
	PublicKey *rsa.PublicKey `json:"-"`
}

// NewRSAJWTKey 新建一个RSAJWTKey
func NewRSAJWTKey(publicKey *rsa.PublicKey) RSAJWTKey {
	key := RSAJWTKey{}
	key.JWTKey.KeyType = "RSA"
	key.Use = "sig"
	key.N = base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	var buf = make([]byte, 8)
	e := uint64(publicKey.E)

	binary.BigEndian.PutUint64(buf, e)
	bytes.TrimLeft(buf, "\x00")

	key.E = base64.RawURLEncoding.EncodeToString(buf)
	key.PublicKey = publicKey
	return key
}

// NewRSAJWTKeyWithPEM 通过pem证书文件内容新建一个RSAJWTKey
func NewRSAJWTKeyWithPEM(pemBytes []byte) RSAJWTKey {

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		slog.Error("public key error")
	}
	// 解析公钥
	pi, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.Error("Public Key Data Error", "error", err)

	}
	return NewRSAJWTKey(pi.(*rsa.PublicKey))
}
