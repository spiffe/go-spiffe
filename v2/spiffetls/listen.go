package spiffetls

import (
	"net"
)

// ListenTLS creates a TLS listener accepting connections on the given network
// address using net.Listen. During the handshake, it presents an SVID
// retrieved from the SVIDStore.
func ListenTLS(net, addr string, store SVIDStore) (net.Listener, error) {
	panic("not implemented")
}

// ListenMTLS creates a MTLS listener accepting connections on the given
// network address using net.Listen. During the handshake, it presents an SVID
// retrieved from the PeerStore. The incoming client certificate is verified
// using X.509 roots retrieved from the PeerStore and the SPIFFE ID of the
// client is validated using the validator.
func ListenMTLS(net, addr string, store PeerStore, validator Validator) (net.Listener, error) {
	panic("not implemented")
}
