package jwkit_test

import (
	"context"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/require"
	"github.com/tangelo-labs/go-jwkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestGRPCUnaryInterceptor(t *testing.T) {
	t.Run("GIVEN an unary grpc handler function AND a valid-signed token in the context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		tk := jwkit.NewTestToolkit(t, 1)
		interceptor := jwkit.NewGRPCUnaryInterceptor(tk)
		unaryInfo := &grpc.UnaryServerInfo{FullMethod: "TestService.UnaryMethod"}
		unaryHandler := func(ctx context.Context, req any) (any, error) {
			return jwkit.TokenFromContext(ctx)
		}

		token := tk.NewToken(ctx).
			Issuer(gofakeit.Name()).
			Expiration(time.Now().Add(24 * time.Hour)).
			Build()

		rawToken, err := tk.Sign(ctx, token)
		require.NoError(t, err)

		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+rawToken))

		t.Run("WHEN jwt interceptor calls the handler THEN the handler receives the validated token and return it", func(t *testing.T) {
			handlerToken, iErr := interceptor(ctx, "xyz", unaryInfo, unaryHandler)

			require.NoError(t, iErr)
			require.NotNil(t, handlerToken)
			require.IsType(t, &jwkit.Token{}, handlerToken)

			interceptedToken, ok := handlerToken.(*jwkit.Token)

			require.True(t, ok)
			require.True(t, interceptedToken.Valid)
		})
	})

	t.Run("GIVEN an unary interceptor built for a concrete toolkit AND a token in the context signed using another toolkit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		tkOne := jwkit.NewTestToolkit(t, 1)
		tkTwo := jwkit.NewTestToolkit(t, 1)
		interceptor := jwkit.NewGRPCUnaryInterceptor(tkOne)
		unaryInfo := &grpc.UnaryServerInfo{FullMethod: "TestService.UnaryMethod"}
		unaryHandler := func(ctx context.Context, req any) (any, error) {
			return jwkit.TokenFromContext(ctx)
		}

		token := tkTwo.NewToken(ctx).
			Issuer(gofakeit.Name()).
			Expiration(time.Now().Add(24 * time.Hour)).
			Build()

		rawToken, err := tkTwo.Sign(ctx, token)
		require.NoError(t, err)

		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+rawToken))

		t.Run("WHEN jwt interceptor calls the handler THEN the handler receives the invalidated token and returns it", func(t *testing.T) {
			handlerToken, iErr := interceptor(ctx, "xyz", unaryInfo, unaryHandler)

			require.NoError(t, iErr)
			require.NotNil(t, handlerToken)
			require.IsType(t, &jwkit.Token{}, handlerToken)

			interceptedToken, ok := handlerToken.(*jwkit.Token)

			require.True(t, ok)
			require.False(t, interceptedToken.Valid)

			issuer, cErr := interceptedToken.Claims.GetIssuer()

			require.NoError(t, cErr)

			expectedIssuer, iErr := token.Claims.GetIssuer()

			require.NoError(t, iErr)
			require.EqualValues(t, expectedIssuer, issuer)
		})
	})
}
