package jwkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

var signingMethods = []jwt.SigningMethod{
	SigningMethodHS256,
	SigningMethodHS384,
	SigningMethodHS512,
	SigningMethodRS256,
	SigningMethodRS384,
	SigningMethodRS512,
	SigningMethodES256,
	SigningMethodES384,
	SigningMethodES512,
	SigningMethodPS256,
	SigningMethodPS384,
	SigningMethodPS512,
	SigningMethodEdDSA,
}

// NewTestToolkit creates a new JWT toolkit with a specified number of key pairs
// for testing purposes.
func NewTestToolkit(t *testing.T, numKeyPairs int) *Toolkit {
	t.Helper()

	pairs := make([]KeyPair, numKeyPairs)

	for i := 0; i < numKeyPairs; i++ {
		pairs[i] = NewTestKeyPair(t)
	}

	tk, err := NewToolkit(context.TODO(), pairs...)
	require.NoError(t, err)

	return tk
}

// NewTestKeyPair generates a random key pair for testing purposes.
func NewTestKeyPair(t *testing.T) KeyPair {
	t.Helper()

	var sKey, vKey interface{}

	sm := signingMethods[gofakeit.Number(0, len(signingMethods)-1)]

	switch sm {
	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512:
		sKey = []byte(gofakeit.Password(true, true, true, false, false, 32))
		vKey = sKey
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512:
		s, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		sKey = s
		vKey = s.Public()
	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		curves := map[SigningMethod]elliptic.Curve{
			SigningMethodES256: elliptic.P256(),
			SigningMethodES384: elliptic.P384(),
			SigningMethodES512: elliptic.P521(),
		}

		s, err := ecdsa.GenerateKey(curves[sm], rand.Reader)
		require.NoError(t, err)

		sKey = s
		vKey = s.Public()
	case SigningMethodPS256, SigningMethodPS384, SigningMethodPS512:
		s, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		sKey = s
		vKey = s.Public()
	case SigningMethodEdDSA:
		v, s, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		sKey = s
		vKey = v
	default:
		require.Fail(t, "unknown signing method")
	}

	return KeyPair{
		ID:            gofakeit.UUID(),
		SigningMethod: sm,
		SigningKey:    sKey,
		VerifyKey:     vKey,
	}
}
