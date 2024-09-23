package jwkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	stdjwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

// Signer is an interface that defines the method for signing a token.
type Signer interface {
	Sign(ctx context.Context, token *Token) (string, error)
}

// Parser is an interface that defines the method for parsing a token.
type Parser interface {
	Parse(ctx context.Context, tokenString string, option ...ParserOption) (*Token, error)
}

// Creator is an interface that defines the method for creating a new token.
type Creator interface {
	NewToken(ctx context.Context) *Builder
}

// KeyStore is an interface that defines methods for managing keys.
type KeyStore interface {
	Fetch(ctx context.Context, url string, options ...FetchOption) error
	RefreshInterval(ctx context.Context, url string, d time.Duration) error
	RegisterKeyPair(ctx context.Context, key KeyPair) error
	VerificationKeys(ctx context.Context) Keys
	SigningKeys(ctx context.Context) Keys
}

type signer struct {
	kid    string
	key    any
	method SigningMethod
}

// Toolkit is an all-in-one solution for dealing with JWT lifecycle.
//
// It provides the ability to build, sign and verify JWT tokens using a set of
// key pairs.
//
// Toolkit is safe for concurrent use.
type Toolkit struct {
	// pairs is the set of key pairs that can be used to sign and verify
	// JWT tokens.
	pairs map[string][]KeyPair

	// privateKeys is a convenience set of private keys that can be used to sign
	// a JWT token.
	privateKeys Keys

	// publicKeys is a convenience set of public keys that can be used to verify
	// a JWT token.
	publicKeys Keys

	// verifiers is a convenience set of verification keys used internally by
	// keyFunc to verify the tokens.
	verifiers stdjwt.VerificationKeySet

	// signers is a convenience slice of signers used internally when building
	// new tokens.
	signers []signer

	mu sync.RWMutex
}

// NewToolkit creates a new JWT toolkit using the provided key pairs.
func NewToolkit(ctx context.Context, pairs ...KeyPair) (*Toolkit, error) {
	tk := &Toolkit{
		pairs:       make(map[string][]KeyPair),
		privateKeys: jwk.NewSet(),
		publicKeys:  jwk.NewSet(),
		verifiers:   stdjwt.VerificationKeySet{Keys: []stdjwt.VerificationKey{}},
		signers:     []signer{},
	}

	for i := range pairs {
		if err := tk.RegisterKeyPair(ctx, pairs[i]); err != nil {
			return tk, err
		}
	}

	return tk, nil
}

func (c *Toolkit) Fetch(ctx context.Context, url string, options ...FetchOption) error {
	set, err := jwk.Fetch(ctx, url, options...)
	if err != nil {
		return err
	}

	n := set.Len()
	if n == 0 {
		return nil
	}

	if uErr := c.unregisterFromSource(url); uErr != nil {
		return uErr
	}

	pairs := make([]KeyPair, 0)

	for i := 0; i < n; i++ {
		if key, ok := set.Get(i); ok {
			pair, pErr := c.jwkToPair(key)
			if pErr != nil {
				return pErr
			}

			pair.Metadata["source"] = url
			pairs = append(pairs, pair)
		}
	}

	return c.RegisterKeyPair(ctx, pairs...)
}

func (c *Toolkit) RefreshInterval(ctx context.Context, url string, d time.Duration) error {
	exists := false

	for _, pairs := range c.pairs {
		for i := range pairs {
			if pairs[i].Metadata["source"] == url {
				exists = true

				break
			}
		}
	}

	if !exists {
		return fmt.Errorf("cannot refresh source `%s` because not found, use Fetch first", url)
	}

	ticker := time.NewTicker(d)

	go func() {
		done := ctx.Done()

		for {
			select {
			case <-done:
				ticker.Stop()

				return
			case <-ticker.C:
				if err := c.Fetch(ctx, url); err != nil {
					println(err.Error())
				}
			}
		}
	}()

	return nil
}

// RegisterKeyPair registers a new key pair in the toolkit.
func (c *Toolkit) RegisterKeyPair(_ context.Context, pairs ...KeyPair) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range pairs {
		if err := pairs[i].validate(); err != nil {
			return err
		}

		if pairs[i].Metadata == nil {
			pairs[i].Metadata = map[string]string{}
		}

		if c.pairs[pairs[i].ID] == nil {
			c.pairs[pairs[i].ID] = []KeyPair{}
		}

		c.pairs[pairs[i].ID] = append(c.pairs[pairs[i].ID], pairs[i])

		if pairs[i].VerifyKey != nil {
			key, err := pairs[i].verKey()
			if err != nil {
				return err
			}

			c.publicKeys.Add(key)
		}

		if pairs[i].SigningKey != nil {
			key, err := pairs[i].signKey()
			if err != nil {
				return err
			}

			c.privateKeys.Add(key)
		}
	}

	c.unsafeRebuildVerifiers()
	c.unsafeRebuildSigners()

	return nil
}

// VerificationKeys returns the set of public keys. It can be used to perform
// verification of JWT tokens.
func (c *Toolkit) VerificationKeys(_ context.Context) Keys {
	c.mu.RLock()
	defer c.mu.RUnlock()

	clone, err := c.publicKeys.Clone()
	if err != nil {
		return jwk.NewSet()
	}

	return clone
}

// SigningKeys returns the set of private keys. It can be used to sign JWT
// tokens.
func (c *Toolkit) SigningKeys(_ context.Context) Keys {
	c.mu.RLock()
	defer c.mu.RUnlock()

	clone, err := c.privateKeys.Clone()
	if err != nil {
		return jwk.NewSet()
	}

	return clone
}

// NewToken starts building a new token using a randomly picked signing key. If
// no key is available, the token will be signed using the `none` method, and
// thus verification/signing will always fail.
func (c *Toolkit) NewToken(_ context.Context) *Builder {
	var (
		sm  stdjwt.SigningMethod = stdjwt.SigningMethodNone
		kid string
	)

	if l := len(c.signers); l > 0 {
		c.mu.RLock()
		sig := c.signers[rand.Intn(l)]
		c.mu.RUnlock()

		sm = sig.method
		kid = sig.kid
	}

	b := NewBuilder(sm)

	if kid != "" {
		return b.Header("kid", kid)
	}

	return b
}

// Sign signs the provided token using.
func (c *Toolkit) Sign(_ context.Context, token *Token) (string, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return "", fmt.Errorf("unable to sign token, key ID not found in headers")
	}

	c.mu.RLock()
	keys, ok := c.pairs[kid]
	c.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("unable to sign token, key ID `%s` not found", kid)
	}

	var pair *KeyPair

	for i := range keys {
		if keys[i].SigningKey != nil {
			pair = &keys[i]

			break
		}
	}

	if pair == nil {
		return "", fmt.Errorf("unable to sign token, key ID `%s` cannot be used for signing", kid)
	}

	s, err := token.SignedString(pair.SigningKey)
	if err != nil {
		return "", err
	}

	return s, nil
}

// Parse parses the provided signed token. This method will not fail on
// signature verification errors. If the token is invalid, you must check the
// [Token.Valid] field.
func (c *Toolkit) Parse(_ context.Context, tokenString string, option ...ParserOption) (*Token, error) {
	token, err := stdjwt.Parse(tokenString, c.keyFunc, option...)
	if errors.Is(err, stdjwt.ErrTokenSignatureInvalid) {
		err = nil
	}

	return token, err
}

func (c *Toolkit) unregisterFromSource(url string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, v := range c.pairs {
		for i := range v {
			if v[i].Metadata["source"] == url {
				delete(c.pairs, k)
			}
		}
	}

	pubKeys, err := c.publicKeys.Clone()
	if err != nil {
		return err
	}

	n := pubKeys.Len()
	for i := 0; i < n; i++ {
		if key, exists := pubKeys.Get(i); exists {
			rawSource, hasSource := key.Get("source")
			if hasSource {
				if src, ok := rawSource.(string); ok && src == url {
					c.publicKeys.Remove(key)
				}
			}
		}
	}

	prvKeys, err := c.privateKeys.Clone()
	if err != nil {
		return err
	}

	m := prvKeys.Len()
	for i := 0; i < m; i++ {
		if key, exists := prvKeys.Get(i); exists {
			rawSource, hasSource := key.Get("source")
			if hasSource {
				if src, ok := rawSource.(string); ok && src == url {
					c.privateKeys.Remove(key)
				}
			}
		}
	}

	c.unsafeRebuildVerifiers()
	c.unsafeRebuildSigners()

	return nil
}

// keyFunc returns the function used to retrieve the key used to verify the JWT
// token.
//
// If the token does not contain a `kid` field, the function will return the
// public key. Otherwise, it will return a `VerificationKeySet` containing the
// all public keys.
func (c *Toolkit) keyFunc(t *Token) (any, error) {
	kid, hasKID := t.Header["kid"].(string)

	if hasKID {
		c.mu.RLock()
		defer c.mu.RUnlock()

		if pairs, exists := c.pairs[kid]; exists {
			return c.buildVKeys(pairs...)
		}
	}

	return c.vKeysClone(), nil
}

func (c *Toolkit) buildVKeys(pairs ...KeyPair) (stdjwt.VerificationKeySet, error) {
	var keys []stdjwt.VerificationKey

	for i := range pairs {
		if pairs[i].VerifyKey != nil {
			keys = append(keys, pairs[i].VerifyKey)
		}
	}

	return stdjwt.VerificationKeySet{Keys: keys}, nil
}

func (c *Toolkit) vKeysClone() stdjwt.VerificationKeySet {
	c.mu.RLock()
	defer c.mu.RUnlock()

	clone := stdjwt.VerificationKeySet{
		Keys: make([]stdjwt.VerificationKey, len(c.verifiers.Keys)),
	}

	copy(clone.Keys, c.verifiers.Keys)

	return clone
}

// unsafeRebuildVerifiers must be called with the mutex locked.
func (c *Toolkit) unsafeRebuildVerifiers() {
	keys := []stdjwt.VerificationKey{}

	for _, pairs := range c.pairs {
		for i := range pairs {
			if pairs[i].VerifyKey != nil {
				keys = append(keys, pairs[i].VerifyKey)
			}
		}
	}

	c.verifiers.Keys = keys
}

// unsafeRebuildSigners must be called with the mutex locked.
func (c *Toolkit) unsafeRebuildSigners() {
	c.signers = nil

	for _, pairs := range c.pairs {
		for i := range pairs {
			if pairs[i].SigningKey != nil {
				c.signers = append(c.signers, signer{
					kid:    pairs[i].ID,
					key:    pairs[i].SigningKey,
					method: pairs[i].SigningMethod,
				})
			}
		}
	}
}

//nolint:gocyclo
func (c *Toolkit) jwkToPair(key jwk.Key) (KeyPair, error) {
	var raw any

	if err := key.Raw(&raw); err != nil {
		return KeyPair{}, err
	}

	out := KeyPair{
		ID:       key.KeyID(),
		Metadata: map[string]string{},
	}

	switch k := raw.(type) {
	case *ed25519.PublicKey:
		out.VerifyKey = k
	case *ed25519.PrivateKey:
		out.SigningKey = k
		out.VerifyKey = k.Public()
	case *ecdsa.PublicKey:
		out.VerifyKey = k
	case *ecdsa.PrivateKey:
		out.SigningKey = k
		out.VerifyKey = k.Public()
	case *rsa.PublicKey:
		out.VerifyKey = k
	case *rsa.PrivateKey:
		out.SigningKey = k
		out.VerifyKey = k.Public()
	case []byte:
		out.SigningKey = k
		out.VerifyKey = k
	}

	switch strings.ToUpper(key.Algorithm()) {
	case "HS256":
		out.SigningMethod = SigningMethodHS256
	case "HS384":
		out.SigningMethod = SigningMethodHS384
	case "HS512":
		out.SigningMethod = SigningMethodHS512
	case "RS256":
		out.SigningMethod = SigningMethodRS256
	case "RS384":
		out.SigningMethod = SigningMethodRS384
	case "RS512":
		out.SigningMethod = SigningMethodRS512
	case "ES256":
		out.SigningMethod = SigningMethodES256
	case "ES384":
		out.SigningMethod = SigningMethodES384
	case "ES512":
		out.SigningMethod = SigningMethodES512
	case "PS256":
		out.SigningMethod = SigningMethodPS256
	case "PS384":
		out.SigningMethod = SigningMethodPS384
	case "PS512":
		out.SigningMethod = SigningMethodPS512
	case "EDDSA":
		out.SigningMethod = SigningMethodEdDSA
	default:
		return KeyPair{}, fmt.Errorf("unsupported algorithm: %s", key.Algorithm())
	}

	return out, nil
}
