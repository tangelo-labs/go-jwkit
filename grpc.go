package jwkit

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// NewGRPCUnaryInterceptor builds a gRPC unary interceptor that extracts the JWT
// token from incoming request headers and stores it in the context. It uses
// the provided KeyFunc to validate the token.
//
// If the token is found but not valid, the interceptor will store the invalid
// token in the context. You can use the token's [Token.Valid] field to check
// if the token is valid or not.
//
// Providing a nil KeyFunc will disable this interceptor.
//
// This interceptor expects the token to be in the `authorization` header in the
// RFC 6750 format, example:
//
// `Authorization: Bearer <token>`.
func NewGRPCUnaryInterceptor(tk *Toolkit) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if tk == nil {
			return handler(ctx, req)
		}

		token, err := tokenFromGRPCRequest(ctx, tk)
		if err != nil {
			return handler(ctx, req)
		}

		ctx = ContextWithToken(ctx, token)

		return handler(ctx, req)
	}
}

// NewGRPCStreamInterceptor similar to NewGRPCUnaryInterceptor, but for server streams.
func NewGRPCStreamInterceptor(tk *Toolkit) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if tk == nil {
			return handler(srv, ss)
		}

		token, err := tokenFromGRPCRequest(ss.Context(), tk)
		if err != nil {
			return handler(srv, ss)
		}

		return handler(srv, &wrappedGRPCServerStream{
			ServerStream: ss,
			ctx:          ContextWithToken(ss.Context(), token),
		})
	}
}

func tokenFromGRPCRequest(ctx context.Context, tk *Toolkit) (*Token, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("metadata not found in context")
	}

	if a := md.Get("authorization"); len(a) > 0 {
		if t, err := TokenFromAuthHeader(ctx, a[0], tk); err == nil {
			return t, nil
		}
	}

	return nil, errors.New("token not found in request")
}

type wrappedGRPCServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedGRPCServerStream) Context() context.Context {
	return w.ctx
}
