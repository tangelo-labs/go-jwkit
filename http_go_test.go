package jwkit_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/require"
	"github.com/tangelo-labs/go-jwkit"
)

func TestNewHTTPMiddleware(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("GIVEN an echo server AND a valid signed token AND an http middleware", func(t *testing.T) {
		tk := jwkit.NewTestToolkit(t, 10)
		token := tk.NewToken(ctx).
			Issuer(gofakeit.Name()).
			Expiration(time.Now().Add(24 * time.Hour)).
			Build()

		signedToken, err := tk.Sign(ctx, token)
		require.NoError(t, err)

		var interceptedToken *jwkit.Token

		handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			tkn, fErr := jwkit.TokenFromContext(req.Context())
			interceptedToken = tkn

			require.NoError(t, fErr)
		})

		middleware := jwkit.NewHTTPMiddleware(tk, handler)

		t.Run("WHEN a request with a valid token passes through the middleware", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/dummy", nil)

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", signedToken))
			middleware.ServeHTTP(httptest.NewRecorder(), req)

			t.Run("THEN the handler intercepts the token from the context AND is valid", func(t *testing.T) {
				require.NotNil(t, interceptedToken)
				require.True(t, interceptedToken.Valid)
			})
		})
	})
}
