package jwkit

import (
	"context"
	"fmt"
	"strings"
)

const bearer string = "bearer"

// TokenFromAuthHeader extracts the JWT token from the `Authorization` header in
// the RFC 6750 format and returns it, for example:
//
// `Authorization: Bearer <token>`.
//
// It uses the provided KeyFunc to validate the token. It the header is invalid,
// or the token is malformed, it will return an error.
//
// If the token is found but not valid, the function will return the token with
// the [Token.Valid] field set to false.
func TokenFromAuthHeader(ctx context.Context, bearerHeader string, tk *Toolkit) (*Token, error) {
	authHeaderParts := strings.Split(bearerHeader, " ")
	if len(authHeaderParts) != 2 || !strings.EqualFold(authHeaderParts[0], bearer) {
		return nil, fmt.Errorf("invalid authorization header `%s`", bearerHeader)
	}

	// Parse the token without signature validation
	return tk.Parse(ctx, authHeaderParts[1])
}
