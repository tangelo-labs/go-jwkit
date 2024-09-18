package jwkit_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	stdjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/tangelo-labs/go-jwkit"
)

const googleCerts = `{
  "keys": [
    {
      "use": "sig",
      "kid": "d7b939771a7800c413f90051012d975981916d71",
      "e": "AQAB",
      "n": "wNHgGSG5B5xOEQNFPW2p_6ZxZbfPoAU5VceBUuNwQWLop0ohW0vpoZLU1tAsq_S9s5iwy27rJw4EZAOGBR9oTRq1Y6Li5pDVJfmzyRNtmWCWndR-bPqhs_dkJU7MbGwcvfLsN9FSHESFrS9sfGtUX-lZfLoGux23TKdYV9EE-H-NDASxrVFUk2GWc3rL6UEMWrMnOqV9-tghybDU3fcRdNTDuXUr9qDYmhmNegYjYu4REGjqeSyIG1tuQxYpOBH-tohtcfGY-oRTS09kgsSS9Q5BRM4qqCkGP28WhlSf4ui0-norS0gKMMI1P_ZAGEsLn9p2TlYMpewvIuhjJs1thw",
      "alg": "RS256",
      "kty": "RSA"
    },
    {
      "alg": "RS256",
      "use": "sig",
      "e": "AQAB",
      "n": "pi22xDdK2fz5gclIbDIGghLDYiRO56eW2GUcboeVlhbAuhuT5mlEYIevkxdPOg5n6qICePZiQSxkwcYMIZyLkZhSJ2d2M6Szx2gDtnAmee6o_tWdroKu0DjqwG8pZU693oLaIjLku3IK20lTs6-2TeH-pUYMjEqiFMhn-hb7wnvH_FuPTjgz9i0rEdw_Hf3Wk6CMypaUHi31y6twrMWq1jEbdQNl50EwH-RQmQ9bs3Wm9V9t-2-_Jzg3AT0Ny4zEDU7WXgN2DevM8_FVje4IgztNy29XUkeUctHsr-431_Iu23JIy6U4Kxn36X3RlVUKEkOMpkDD3kd81JPW4Ger_w",
      "kid": "b2620d5e7f132b52afe8875cdf3776c064249d04",
      "kty": "RSA"
    }
  ]
}`

func TestNewToolkit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("GIVEN a toolkit instance with a set of key pairs", func(t *testing.T) {
		pairs := []jwkit.KeyPair{
			{
				ID:            gofakeit.UUID(),
				SigningKey:    []byte("TEST_SIGNING_KEY_ONE"),
				VerifyKey:     []byte("TEST_SIGNING_KEY_ONE"),
				SigningMethod: stdjwt.SigningMethodHS256,
			},
			{
				ID:            gofakeit.UUID(),
				SigningKey:    []byte("TEST_SIGNING_KEY_TWO"),
				VerifyKey:     []byte("TEST_SIGNING_KEY_TWO"),
				SigningMethod: stdjwt.SigningMethodHS256,
			},
			{
				ID:            gofakeit.UUID(),
				SigningKey:    []byte("TEST_SIGNING_KEY_THREE"),
				VerifyKey:     []byte("TEST_SIGNING_KEY_THREE"),
				SigningMethod: stdjwt.SigningMethodHS256,
			},
			{
				ID:            gofakeit.UUID(),
				SigningKey:    []byte("TEST_SIGNING_KEY_FOUR"),
				VerifyKey:     []byte("TEST_SIGNING_KEY_FOUR"),
				SigningMethod: stdjwt.SigningMethodHS256,
			},
		}

		kit, err := jwkit.NewToolkit(ctx, pairs...)
		require.NoError(t, err)

		t.Run("WHEN a token is built using the first key pair THEN a not nil token is created", func(t *testing.T) {
			token := kit.NewToken(ctx).Build()
			require.NotNil(t, token)

			t.Run("WHEN the token is signed THEN a not empty signed token is returned", func(t *testing.T) {
				signed, err := kit.Sign(ctx, token)
				require.NotEmpty(t, signed)
				require.NoError(t, err)
			})
		})
	})

	t.Run("GIVEN an empty set of key paris", func(t *testing.T) {
		pairs := []jwkit.KeyPair{}

		t.Run("WHEN creating a new toolkit instance THEN no errors are raised AND an empty toolkit is returned", func(t *testing.T) {
			_, err := jwkit.NewToolkit(ctx, pairs...)
			require.NoError(t, err)
		})
	})

	t.Run("GIVEN an empty toolkit WHEN signing a token created with such toolkit THEN signature fails", func(t *testing.T) {
		tk, err := jwkit.NewToolkit(ctx)
		require.NoError(t, err)

		token := tk.NewToken(ctx).Build()
		require.NotNil(t, token)

		signed, err := tk.Sign(ctx, token)
		require.Empty(t, signed)
		require.Error(t, err)
	})

	t.Run("GIVEN a toolkit with a verification key intended for HS256", func(t *testing.T) {
		tk, err := jwkit.NewToolkit(ctx)
		require.NoError(t, err)

		err = tk.RegisterKeyPair(ctx, jwkit.KeyPair{
			ID:            "secret key",
			VerifyKey:     []byte("secret"),
			SigningMethod: stdjwt.SigningMethodHS256,
		})

		require.NoError(t, err)

		t.Run("WHEN parsing a token signed with such key THEN the token is parsed successfully", func(t *testing.T) {
			stringToken := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o`
			token, err := tk.Parse(ctx, stringToken)

			require.NoError(t, err)
			require.NotNil(t, token)
			require.True(t, token.Valid)
		})

		t.Run("WHEN building a new token using such key THEN token is built but cannot be signed", func(t *testing.T) {
			sub := "1234567890"
			token := tk.NewToken(ctx).Subject(sub).Build()

			require.NotNil(t, token)
			require.False(t, token.Valid)

			gotSubject, err := token.Claims.GetSubject()

			require.NoError(t, err)
			require.Equal(t, sub, gotSubject)

			signed, err := tk.Sign(ctx, token)
			require.Empty(t, signed)
			require.Error(t, err)
		})
	})

	t.Run("GIVEN an empty toolkit", func(t *testing.T) {
		tk, err := jwkit.NewToolkit(ctx)
		require.NoError(t, err)

		t.Run("WHEN adding a verification key only but missing the signing method THEN an error is raised", func(t *testing.T) {
			err = tk.RegisterKeyPair(ctx, jwkit.KeyPair{
				ID:        "secret",
				VerifyKey: []byte("secret"),
			})

			require.Error(t, err)
		})

		t.Run("WHEN adding a verification key as HS256 THEN no error is raised", func(t *testing.T) {
			err = tk.RegisterKeyPair(ctx, jwkit.KeyPair{
				ID:            "secret",
				SigningMethod: stdjwt.SigningMethodHS256,
				VerifyKey:     []byte("secret"),
			})

			require.NoError(t, err)
		})
	})

	t.Run("GIVEN an empty toolkit", func(t *testing.T) {
		tk, err := jwkit.NewToolkit(ctx)
		require.NoError(t, err)

		t.Run("WHEN adding a signing key only but missing the signing method THEN an error is raised", func(t *testing.T) {
			err = tk.RegisterKeyPair(ctx, jwkit.KeyPair{
				ID:         "secret",
				SigningKey: []byte("secret"),
			})

			require.Error(t, err)
		})

		t.Run("WHEN adding a signing key only as HS256 THEN no error is raised", func(t *testing.T) {
			err = tk.RegisterKeyPair(ctx, jwkit.KeyPair{
				ID:            "secret",
				SigningMethod: stdjwt.SigningMethodHS256,
				SigningKey:    []byte("secret"),
			})

			require.NoError(t, err)
		})
	})

	t.Run("GIVEN an empty toolkit", func(t *testing.T) {
		tk, err := jwkit.NewToolkit(ctx)
		require.NoError(t, err)

		t.Run("WHEN adding a RSA signing key with ECDSA method THEN an error is raised", func(t *testing.T) {
			privateKey, gErr := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, gErr)

			key := jwkit.KeyPair{
				ID:            gofakeit.UUID(),
				SigningKey:    privateKey,
				VerifyKey:     privateKey.Public(),
				SigningMethod: stdjwt.SigningMethodES384,
			}

			require.Error(t, tk.RegisterKeyPair(ctx, key))
		})
	})
}

func Test_Toolkit_Fetch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("GIVEN an empty toolkit AND a http server that returns two google certs", func(t *testing.T) {
		tk, err := jwkit.NewToolkit(ctx)
		require.NoError(t, err)

		fakeServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, wErr := w.Write([]byte(googleCerts))
				require.NoError(t, wErr)
			}),
		)

		defer fakeServer.Close()

		t.Run("WHEN fetching keys from the server THEN the toolkit contains both keys", func(t *testing.T) {
			fErr := tk.Fetch(ctx, fakeServer.URL)

			require.NoError(t, fErr)
			require.Equal(t, 2, tk.VerificationKeys(ctx).Len())
		})
	})
}

func Test_Toolkit_Refresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("GIVEN an empty toolkit AND a http server that returns two google certs", func(t *testing.T) {
		tk, err := jwkit.NewToolkit(ctx)
		require.NoError(t, err)

		serves := &atomic.Int32{}

		fakeServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, wErr := w.Write([]byte(googleCerts))
				require.NoError(t, wErr)

				serves.Add(1)
			}),
		)

		defer fakeServer.Close()

		t.Run("WHEN fetching and refreshing each millisecond THEN eventually keys are retrieved more than once", func(t *testing.T) {
			fErr := tk.Fetch(ctx, fakeServer.URL)
			require.NoError(t, fErr)

			rErr := tk.RefreshInterval(ctx, fakeServer.URL, 1*time.Millisecond)
			require.NoError(t, rErr)

			require.Eventually(t, func() bool {
				return serves.Load() > 1
			}, 5*time.Second, 100*time.Millisecond)
		})
	})
}
