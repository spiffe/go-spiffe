package spiffehttp

import (
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Validator validates an incoming HTTP request.
type Validator func(id spiffeid.ID, r *http.Request) error
