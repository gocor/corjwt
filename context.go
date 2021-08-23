package corjwt

import (
	"context"

	"github.com/dgrijalva/jwt-go"
)

type ctxKey int

const tokenKey ctxKey = ctxKey(0)

// FromContext extracts the token from the context if it exists
func FromContext(ctx context.Context) *jwt.Token {
	token, ok := ctx.Value(tokenKey).(*jwt.Token)
	if !ok {
		return nil
	}
	return token
}

// ContextWithToken will give a new context with the token provided
func ContextWithToken(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}
