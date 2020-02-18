package workloadapi

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"gopkg.in/square/go-jose.v2"
)

// X509ContextWatcher receives X509Context updates from the Workload API.
type X509ContextWatcher interface {
	OnX509ContextUpdate(*X509Context)
	OnX509ContextWatchError(error)
}

// JWTBundleWatcher receives JWT bundle updates from the Workload API.
type JWTBundleWatcher interface {
	OnJWTBundleUpdate(map[spiffeid.TrustDomain]jose.JSONWebKeySet)
	OnJWTBundleWatchError(error)
}
