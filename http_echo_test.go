package jwkit_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/tangelo-labs/go-jwkit"
)

func TestNewEchoMiddleware(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("GIVEN an echo server AND a valid signed token AND a jwt middleware", func(t *testing.T) {
		e := echo.New()

		tk := jwkit.NewTestToolkit(t, 1)
		token := tk.NewToken(ctx).
			Issuer(gofakeit.Name()).
			Expiration(time.Now().Add(24 * time.Hour)).
			Build()

		signedToken, err := tk.Sign(ctx, token)
		require.NoError(t, err)

		middleware := jwkit.NewEchoMiddleware(tk)

		t.Run("WHEN a request with a valid token passes through the middleware to a handler", func(t *testing.T) {
			var interceptedToken *jwkit.Token

			handler := func(c echo.Context) error {
				tk, fErr := jwkit.TokenFromContext(c.Request().Context())
				interceptedToken = tk

				return fErr
			}

			req := httptest.NewRequest(http.MethodGet, "https://example.com/dummy", nil)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", signedToken))

			c := e.NewContext(req, httptest.NewRecorder())

			err = middleware(handler)(c)

			t.Run("THEN the handler intercepts the token from the context AND is valid", func(t *testing.T) {
				require.NoError(t, err)

				require.NotNil(t, interceptedToken)
				require.True(t, interceptedToken.Valid)
			})
		})
	})
}
