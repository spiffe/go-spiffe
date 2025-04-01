package spiffetls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type PeerIDGetter interface {
	PeerID() (spiffeid.ID, error)
}

// PeerIDFromConn returns the peer ID from a server or client peer connection.
// The handshake must have been completed. Note that in Go's TLS stack, the TLS
// 1.3 handshake may not complete until the first read from the connection.
func PeerIDFromConn(conn net.Conn) (spiffeid.ID, error) {
	if getter, ok := conn.(PeerIDGetter); ok {
		return getter.PeerID()
	}
	return spiffeid.ID{}, wrapSpiffetlsErr(errors.New("connection does not expose peer ID"))
}

func PeerIDFromConnectionState(state tls.ConnectionState) (spiffeid.ID, error) {
	// The connection state unfortunately does not have VerifiedChains set
	// because SPIFFE TLS does custom verification, i.e., Go's TLS stack only
	// sets VerifiedChains if it is the one to verify the chain of trust. The
	// SPIFFE ID must be extracted from the peer certificates.
	if len(state.PeerCertificates) == 0 {
		return spiffeid.ID{}, wrapSpiffetlsErr(errors.New("no peer certificates"))
	}
	id, err := x509svid.IDFromCert(state.PeerCertificates[0])
	if err != nil {
		return spiffeid.ID{}, wrapSpiffetlsErr(fmt.Errorf("invalid peer certificate: %w", err))
	}
	return id, nil
}
