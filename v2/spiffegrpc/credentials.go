package spiffegrpc

import (
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffex509"
	"google.golang.org/grpc/credentials"
)

// TLSClientCredentials creates client TLS transport credentials that verify
// and validate server X509-SVIDs using the given root store and validator.
func TLSClientCredentials(config spiffex509.RootStore, validator spiffetls.Validator) credentials.TransportCredentials {
	panic("not implemented")
}

// MTLSClientCredentials creates client mTLS transport credentials that verify
// and validate server X509-SVIDs using the given peer store and validator. The
// peer store also provides the X509-SVID for the client in the TLS handshake.
func MTLSClientCredentials(config spiffetls.PeerStore, validator spiffetls.Validator) credentials.TransportCredentials {
	panic("not implemented")
}

// TLSServerCredentials creates server TLS transport credentials that use the
// given SVID store to provide X509-SVIDs for the server TLS handshake.
func TLSServerCredentials(config spiffetls.SVIDStore) credentials.TransportCredentials {
	panic("not implemented")
}

// MTLSServerCredentials creates server mTLS transport credentials that use the
// given peer store to provide X509-SVIDs for the server TLS handshake. Client
// X509-SVIDs are verified and validated using the peer store and given
// validator.
func MTLSServerCredentials(config spiffetls.PeerStore, validator spiffetls.Validator) credentials.TransportCredentials {
	panic("not implemented")
}
