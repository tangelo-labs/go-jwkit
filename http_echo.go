package jwkit

import (
	"github.com/labstack/echo/v4"
)

// NewEchoMiddleware returns a middleware that extracts the JWT token from the
// `Authorization` header in the RFC 6750 format and stores it in the context.
//
// It uses the provided KeyFunc to validate the token.
func NewEchoMiddleware(tk *Toolkit) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			ctx := req.Context()

			if a := req.Header.Get("Authorization"); len(a) > 0 {
				if t, err := TokenFromAuthHeader(ctx, a, tk); err == nil {
					ctx = ContextWithToken(req.Context(), t)

					c.SetRequest(req.WithContext(ctx))
				}
			}

			return next(c)
		}
	}
}
