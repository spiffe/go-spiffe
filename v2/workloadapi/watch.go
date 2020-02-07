package workloadapi

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"gopkg.in/square/go-jose.v2"
)

type X509ContextWatcher interface {
	OnX509ContextUpdate(*X509Context)
	OnX509ContextWatchError(error)
}

type JWTBundleWatcher interface {
	OnJWTBundleUpdate(map[spiffeid.TrustDomain]jose.JSONWebKeySet)
	OnJWTBundleWatchError(error)
}
