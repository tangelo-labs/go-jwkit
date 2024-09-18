#  JWKit

[![go test](https://github.com/tangelo-labs/go-jwkit/actions/workflows/go-test.yml/badge.svg)](https://github.com/tangelo-labs/go-jwkit/actions/workflows/go-test.yml)
[![golangci-lint](https://github.com/tangelo-labs/go-jwkit/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/tangelo-labs/go-jwkit/actions/workflows/golangci-lint.yml)

This package moves around a "Toolkit" concept, which acts as an all-in-one solution
for JWT-related tasks. It provides utilities for creating, parsing, and
validating JWTs, as well as handling claims and signing algorithms.

## Installation

```bash
go get github.com/tangelo-labs/go-jwkit
```

## Examples

Loading JWK from a URL

```go
package main

import (
    "context"

    "github.com/tangelo-labs/go-jwkit"
)

func main() {
    ctx := context.TODO()
    toolkit := jwkit.NewToolkit()

    // Load verification keys from a URL
    if err: err := toolkit.Fetch(ctx, "https://example.com/jwks.json"); err != nil {
        panic(err)
    }

    // Parse a JWT
    token, err := toolkit.Parse(ctx, "JWT_TOKEN")
    if err != nil {
        panic(err)
    }
}
```
