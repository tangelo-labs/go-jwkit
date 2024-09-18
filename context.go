package jwkit

import (
	"context"
	"errors"
)

var tokenKey = &struct{ name string }{"token"}

// ErrTokenNotFound is returned when the Token is not found in the context.
var ErrTokenNotFound = errors.New("token not found in context")

// TokenFromContext extracts from the given context the Token, if any.
// A not-found error is returned if the Token is not found.
func TokenFromContext(ctx context.Context) (*Token, error) {
	t, ok := ctx.Value(tokenKey).(*Token)
	if !ok {
		return nil, ErrTokenNotFound
	}

	return t, nil
}

// ContextWithToken returns a new context with the given Token attached.
func ContextWithToken(ctx context.Context, token *Token) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}
