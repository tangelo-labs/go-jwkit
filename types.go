package jwkit

import (
	stdjwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

// Token represents a JSON Web Token.
type Token = stdjwt.Token

// KeyFunc will be used by the Parse methods as a callback function to supply
// the key for verification.  The function receives the parsed, but unverified
// Token.  This allows you to use properties in the Header of the token (such as
// `kid`) to identify which key to use.
//
// The returned any may be a single key or a VerificationKeySet containing
// multiple keys.
type KeyFunc = stdjwt.Keyfunc

// SigningMethod can be used add new methods for signing or verifying tokens. It
// takes a decoded signature as an input in the Verify function and produces a
// signature in Sign. The signature is then usually base64 encoded as part of a
// JWT.
type SigningMethod = stdjwt.SigningMethod

// ParserOption is used to implement functional-style options that modify the
// behavior of the parser. To add new options, just create a function (ideally
// beginning with With or Without) that returns an anonymous function that takes
// a *Parser type as input and manipulates its configuration accordingly.
type ParserOption = stdjwt.ParserOption

// Keys represents JWKS object, a collection of jwk.Key objects.
//
// Sets can be safely converted to and from JSON using the standard
// `"encoding/json".Marshal` and `"encoding/json".Unmarshal`. However,
// if you do not know if the payload contains a single JWK or a JWK set,
// consider using `jwk.Parse()` to always get a `jwk.Set` out of it.
//
// Since v1.2.12, JWK sets with private parameters can be parsed as well.
// Such private parameters can be accessed via the `Field()` method.
// If a resource contains a single JWK instead of a JWK set, private parameters
// are stored in _both_ the resulting `jwk.Set` object and the `jwk.Key` object .
type Keys = jwk.Set

// Claims represent any form of a JWT Claims Set according to
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.
type Claims stdjwt.Claims

// MapClaims is a claims type that uses the map[string]any for JSON
// decoding. This is the default claims type if you don't supply one.
type MapClaims = stdjwt.MapClaims

// FetchOption is a type of Option that can be passed to `jwk.Fetch()`
// FetchOption also implements the `AutoRefreshOption`, and thus can
// safely be passed to `(*jwk.AutoRefresh).Configure()`.
type FetchOption = jwk.FetchOption

// Signing methods.
var (
	SigningMethodNone  = stdjwt.SigningMethodNone
	SigningMethodHS256 = stdjwt.SigningMethodHS256
	SigningMethodHS384 = stdjwt.SigningMethodHS384
	SigningMethodHS512 = stdjwt.SigningMethodHS512
	SigningMethodRS256 = stdjwt.SigningMethodRS256
	SigningMethodRS384 = stdjwt.SigningMethodRS384
	SigningMethodRS512 = stdjwt.SigningMethodRS512
	SigningMethodES256 = stdjwt.SigningMethodES256
	SigningMethodES384 = stdjwt.SigningMethodES384
	SigningMethodES512 = stdjwt.SigningMethodES512
	SigningMethodPS256 = stdjwt.SigningMethodPS256
	SigningMethodPS384 = stdjwt.SigningMethodPS384
	SigningMethodPS512 = stdjwt.SigningMethodPS512
	SigningMethodEdDSA = stdjwt.SigningMethodEdDSA
)
