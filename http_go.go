package jwkit

import "net/http"

// NewHTTPMiddleware takes the provided Handler and returns a new Handler that
// extracts the JWT token from the `Authorization` header in the RFC 6750 format
// and stores it in the request context.
func NewHTTPMiddleware(toolkit *Toolkit, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		if a := req.Header.Get("Authorization"); len(a) > 0 {
			if token, err := TokenFromAuthHeader(ctx, a, toolkit); err == nil {
				ctx = ContextWithToken(ctx, token)
				req = req.WithContext(ctx)
			}
		}

		handler.ServeHTTP(w, req)
	})
}
