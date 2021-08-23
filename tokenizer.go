package corjwt

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// Tokenizer ...
type Tokenizer interface {
	NewWithClaims(claims jwt.Claims) (string, error)
	ParseWithClaims(tokenString string) (*jwt.Token, error)
}

type tokenizer struct {
	signingMethod jwt.SigningMethod
	publicKey     interface{}
	privateKey    interface{}
	emptyClaims   jwt.Claims
}

// NewTokenizer will return a new tokenizer.
// For RSA use rsa.PrivateKey and rsa.PublicKey.
// For HMAC double the key.
// emptyClaims is an empty claims object used for token validation
func NewTokenizer(
	signingMethod jwt.SigningMethod,
	privateKey interface{}, publicKey interface{},
	emptyClaims jwt.Claims) Tokenizer {
	return &tokenizer{
		signingMethod: signingMethod,
		privateKey:    privateKey,
		publicKey:     publicKey,
		emptyClaims:   emptyClaims,
	}
}

// NewWithClaims makes a JwtToken string
func (t *tokenizer) NewWithClaims(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(t.signingMethod, claims)
	s, err := token.SignedString(t.privateKey)
	if err != nil {
		return "", err
	}
	return s, nil
}

// ParseWithClaims validates a token and its claims
func (t *tokenizer) ParseWithClaims(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, t.emptyClaims, func(token *jwt.Token) (interface{}, error) {
		return t.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	// Validate signing method on token
	if token.Method == nil {
		return nil, errors.New("Missing signing method")
	}
	if jwt.GetSigningMethod(token.Method.Alg()) != t.signingMethod {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}

	return token, nil
}
