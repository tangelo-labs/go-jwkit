package jwkit

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"
)

type connectInterceptor struct {
	toolkit *Toolkit
}

// NewConnectInterceptor builds a ConnectRPC interceptor that extracts the JWT
// token from incoming request headers and stores it in the context. It uses
// // the provided Toolkit to validate the token.
//
// If the token is found but not valid, the interceptor will store the invalid
// token in the context. You can use the token's [Token.Valid] field to check
// if the token is valid or not.
//
// Providing a nil Toolkit will disable this interceptor.
//
// This interceptor expects the token to be in the `authorization` header in the
// RFC 6750 format, example:
//
// `Authorization: Bearer <token>`.
func NewConnectInterceptor(tk *Toolkit) connect.Interceptor {
	return &connectInterceptor{toolkit: tk}
}

func (c *connectInterceptor) WrapUnary(unaryFunc connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		token, err := c.tokenFromHeaders(ctx, request.Header(), c.toolkit)
		if err == nil {
			ctx = ContextWithToken(ctx, token)
		}

		return unaryFunc(ctx, request)
	}
}

func (c *connectInterceptor) WrapStreamingClient(clientFunc connect.StreamingClientFunc) connect.StreamingClientFunc {
	return clientFunc
}

func (c *connectInterceptor) WrapStreamingHandler(handlerFunc connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		token, err := c.tokenFromHeaders(ctx, conn.RequestHeader(), c.toolkit)
		if err == nil {
			ctx = ContextWithToken(ctx, token)
		}

		return handlerFunc(ctx, conn)
	}
}

func (c *connectInterceptor) tokenFromHeaders(ctx context.Context, headers http.Header, tk *Toolkit) (*Token, error) {
	if tk == nil {
		return nil, errors.New("connect interceptor disabled")
	}

	if a := headers.Get("authorization"); a != "" {
		if t, err := TokenFromAuthHeader(ctx, a, tk); err == nil {
			return t, nil
		}
	}

	return nil, errors.New("token not found in request")
}
