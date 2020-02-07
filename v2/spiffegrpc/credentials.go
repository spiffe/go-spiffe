package spiffegrpc

import (
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffex509"
	"google.golang.org/grpc/credentials"
)

func TLSClientCredentials(config spiffex509.RootStore, validator spiffetls.Validator) credentials.TransportCredentials {
	panic("not implemented")
}

func MTLSClientCredentials(config spiffetls.PeerStore, validator spiffetls.Validator) credentials.TransportCredentials {
	panic("not implemented")
}

func TLSServerCredentials(config spiffetls.SVIDStore) credentials.TransportCredentials {
	panic("not implemented")
}

func MTLSServerCredentials(config spiffetls.PeerStore, validator spiffetls.Validator) credentials.TransportCredentials {
	panic("not implemented")
}
