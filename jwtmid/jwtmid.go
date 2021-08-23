package jwtmid

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"gitlab.com/gocor/corjwt"
)

// AuthHandlerConfig ...
type AuthHandlerConfig struct {
	SigningMethod jwt.SigningMethod
	PublicKey     interface{}
	Options       []request.ParseFromRequestOption
	Extractor     request.Extractor
}

// AuthorizationHandler returns a handler to look for a jwt token and inject it
// into the request context
func AuthorizationHandler(cfg *AuthHandlerConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return authorize(cfg)(next)
	}
}

func authorize(cfg *AuthHandlerConfig) func(http.Handler) http.Handler {
	kf := keyFunc(cfg)
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			token, err := request.ParseFromRequest(
				r,
				cfg.Extractor,
				kf,
				cfg.Options...,
			)

			if err == nil && token.Valid {
				newCtx := corjwt.ContextWithToken(r.Context(), token)
				next.ServeHTTP(w, r.WithContext(newCtx))
				return
			}
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
		}
		return http.HandlerFunc(hfn)
	}
}

func keyFunc(cfg *AuthHandlerConfig) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// verify signing method
		if jwt.GetSigningMethod(token.Method.Alg()) != cfg.SigningMethod {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return cfg.PublicKey, nil
	}
}
