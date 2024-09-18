package jwkit

import (
	"time"

	stdjwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwt"
)

// Builder is a convenience struct that helps to build a new token.
type Builder struct {
	method SigningMethod
	header map[string]any
	claims MapClaims
}

// NewBuilder start building a new token using the provided signing method.
func NewBuilder(method SigningMethod) *Builder {
	return &Builder{
		method: method,
		header: make(map[string]any),
		claims: make(MapClaims),
	}
}

// Audience sets the audience claim of the token ("aud").
func (b *Builder) Audience(v []string) *Builder {
	return b.Claim(jwt.AudienceKey, v)
}

// Expiration sets the expiration claim of the token ("exp").
func (b *Builder) Expiration(v time.Time) *Builder {
	return b.Claim(jwt.ExpirationKey, stdjwt.NewNumericDate(v))
}

// IssuedAt sets the issued-at claim of the token ("iat").
func (b *Builder) IssuedAt(v time.Time) *Builder {
	return b.Claim(jwt.IssuedAtKey, stdjwt.NewNumericDate(v))
}

// Issuer sets the issuer claim of the token ("iss").
func (b *Builder) Issuer(v string) *Builder {
	return b.Claim(jwt.IssuerKey, v)
}

// JwtID sets the JWT ID claim of the token ("jti").
func (b *Builder) JwtID(v string) *Builder {
	return b.Claim(jwt.JwtIDKey, v)
}

// NotBefore sets the not-before claim of the token ("nbf").
func (b *Builder) NotBefore(v time.Time) *Builder {
	return b.Claim(jwt.NotBeforeKey, stdjwt.NewNumericDate(v))
}

// Subject sets the subject claim of the token ("sub").
func (b *Builder) Subject(v string) *Builder {
	return b.Claim(jwt.SubjectKey, v)
}

// Claim sets a custom claim in the token.
func (b *Builder) Claim(name string, value any) *Builder {
	b.claims[name] = value

	return b
}

// Header sets a custom header in the token, if already present it will be
// overwritten.
func (b *Builder) Header(name string, value any) *Builder {
	b.header[name] = value

	return b
}

// Build creates a new token based on the claims that the builder has received
// so far.
func (b *Builder) Build() *Token {
	t := stdjwt.NewWithClaims(b.method, b.claims)

	for k, v := range b.header {
		t.Header[k] = v
	}

	return t
}
