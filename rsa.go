package corjwt

import (
	"crypto/rsa"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

// PrivateRSAFromPemFile ...
func PrivateRSAFromPemFile(fileName string) (*rsa.PrivateKey, error) {
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return PrivateRSA(contents)
}

// PrivateRSA ...
func PrivateRSA(contents []byte) (*rsa.PrivateKey, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(contents)
	if err != nil {
		return nil, err
	}
	return key, err
}

// PublicRSAFromPemFile ...
func PublicRSAFromPemFile(fileName string) (*rsa.PublicKey, error) {
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return PublicRSA(contents)
}

// PublicRSA ...
func PublicRSA(contents []byte) (*rsa.PublicKey, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(contents)
	if err != nil {
		return nil, err
	}
	return key, err
}
