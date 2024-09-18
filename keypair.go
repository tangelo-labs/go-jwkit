package jwkit

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

// ErrInvalidKeyPair is returned when a key pair is invalid.
var ErrInvalidKeyPair = errors.New("invalid key pair")

// KeyPair aggregates the signing and verification keys for a specific key ID.
//
// Both, ID and SigningMethod are required. The SigningKey and VerifyKey are
// optional, but at least one of them must be provided.
//
// If both keys are provided, they are expected to be compatible with each
// other, that is, the SigningKey must be able to sign tokens that can be
// verified with the VerifyKey.
//
// When only one of the keys is provided, such KeyPair can only be used only to
// verify OR sign tokens (depending on which key is provided).
type KeyPair struct {
	// ID uniquely identifies this pair of keys within the Toolkit.
	ID string

	// SigningMethod is the method used to sign new tokens (rsa, hmac, etc).
	SigningMethod SigningMethod

	// SigningKey is the key used to sign new tokens.
	SigningKey any

	// VerifyKey is the key used to verify tokens.
	VerifyKey any

	// Metadata can hold additional information about the key pair.
	Metadata map[string]string
}

func (kp KeyPair) verKey() (jwk.Key, error) {
	key, nErr := jwk.New(kp.VerifyKey)
	if nErr != nil {
		return nil, fmt.Errorf("%w: jwt configuration failed to create JWK from verification key", nErr)
	}

	if err := key.Set(jwk.KeyIDKey, kp.ID); err != nil {
		return nil, fmt.Errorf("%w: jwt configuration failed to set key ID", err)
	}

	if err := key.Set(jwk.AlgorithmKey, kp.SigningMethod.Alg()); err != nil {
		return nil, fmt.Errorf("%w: jwt configuration failed to set algorithm", err)
	}

	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("%w: jwt configuration failed to set key usage", err)
	}

	for k, v := range kp.Metadata {
		if err := key.Set(k, v); err != nil {
			return nil, fmt.Errorf("%w: jwt configuration failed to set metadata key %s", err, k)
		}
	}

	return key, nil
}

func (kp KeyPair) signKey() (jwk.Key, error) {
	key, nErr := jwk.New(kp.SigningKey)
	if nErr != nil {
		return nil, fmt.Errorf("%w: jwt configuration failed to create JWK from verification key", nErr)
	}

	if err := key.Set(jwk.KeyIDKey, kp.ID); err != nil {
		return nil, fmt.Errorf("%w: jwt configuration failed to set key ID", err)
	}

	if err := key.Set(jwk.AlgorithmKey, kp.SigningMethod.Alg()); err != nil {
		return nil, fmt.Errorf("%w: jwt configuration failed to set algorithm", err)
	}

	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, fmt.Errorf("%w: jwt configuration failed to set key usage", err)
	}

	for k, v := range kp.Metadata {
		if err := key.Set(k, v); err != nil {
			return nil, fmt.Errorf("%w: jwt configuration failed to set metadata key %s", err, k)
		}
	}

	return key, nil
}

func (kp KeyPair) validate() error {
	if kp.ID == "" {
		return fmt.Errorf("%w: missing key ID", ErrInvalidKeyPair)
	}

	if kp.SigningMethod == nil {
		return fmt.Errorf("%w: missing signing method", ErrInvalidKeyPair)
	}

	hasPrivateKey := kp.SigningKey != nil
	hasPublicKey := kp.VerifyKey != nil

	if !hasPrivateKey && !hasPublicKey {
		return fmt.Errorf("%w: missing signing and verification keys, at least one must be provided", ErrInvalidKeyPair)
	}

	if hasPrivateKey {
		payload := "random"
		signed, sErr := kp.SigningMethod.Sign(payload, kp.SigningKey)

		if sErr != nil {
			return fmt.Errorf("%w: failed to sign using the provided key and method (`%s`), check that your private key match fits the specified method (details: %w)", ErrInvalidKeyPair, kp.SigningMethod.Alg(), sErr)
		}

		if hasPublicKey {
			if vErr := kp.SigningMethod.Verify(payload, signed, kp.VerifyKey); vErr != nil {
				return fmt.Errorf("%w: failed to verify using the provided key, check that your public key matches the private key (details: %w)", ErrInvalidKeyPair, vErr)
			}
		}
	}

	return nil
}
