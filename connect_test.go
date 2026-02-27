package jwkit_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/require"
	"github.com/tangelo-labs/go-jwkit"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestConnectUnaryInterceptor(t *testing.T) {
	t.Run("GIVEN an unary connect handler AND a valid-signed token in the request headers", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		tk := jwkit.NewTestToolkit(t, 1)
		interceptor := jwkit.NewConnectInterceptor(tk)

		var handlerToken *jwkit.Token

		var handlerErr error

		unaryHandler := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			handlerToken, handlerErr = jwkit.TokenFromContext(ctx)

			return connect.NewResponse(&emptypb.Empty{}), nil
		}

		token := tk.NewToken(ctx).
			Issuer(gofakeit.Name()).
			Expiration(time.Now().Add(24 * time.Hour)).
			Build()

		rawToken, err := tk.Sign(ctx, token)
		require.NoError(t, err)

		req := connect.NewRequest(&emptypb.Empty{})
		req.Header().Set("authorization", "Bearer "+rawToken)

		_, callErr := interceptor.WrapUnary(unaryHandler)(ctx, req)

		require.NoError(t, callErr)
		require.NoError(t, handlerErr)
		require.NotNil(t, handlerToken)
		require.True(t, handlerToken.Valid)
	})

	t.Run("GIVEN an unary connect interceptor tied to one toolkit AND a token signed with another toolkit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		tkOne := jwkit.NewTestToolkit(t, 1)
		tkTwo := jwkit.NewTestToolkit(t, 1)
		interceptor := jwkit.NewConnectInterceptor(tkOne)

		var handlerToken *jwkit.Token

		var handlerErr error

		unaryHandler := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			handlerToken, handlerErr = jwkit.TokenFromContext(ctx)

			return connect.NewResponse(&emptypb.Empty{}), nil
		}

		token := tkTwo.NewToken(ctx).
			Issuer(gofakeit.Name()).
			Expiration(time.Now().Add(24 * time.Hour)).
			Build()

		rawToken, err := tkTwo.Sign(ctx, token)
		require.NoError(t, err)

		req := connect.NewRequest(&emptypb.Empty{})
		req.Header().Set("authorization", "Bearer "+rawToken)

		_, callErr := interceptor.WrapUnary(unaryHandler)(ctx, req)

		require.NoError(t, callErr)
		require.NoError(t, handlerErr)
		require.NotNil(t, handlerToken)
		require.False(t, handlerToken.Valid)

		issuer, cErr := handlerToken.Claims.GetIssuer()
		require.NoError(t, cErr)

		expectedIssuer, iErr := token.Claims.GetIssuer()
		require.NoError(t, iErr)
		require.EqualValues(t, expectedIssuer, issuer)
	})
}
