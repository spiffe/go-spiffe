package workloadapi

import (
	"github.com/spiffe/go-spiffe/v2/spiffex509"
)

// X509Context conveys X.509 materials from the Workload API.
type X509Context struct {
	// SVIDs is a list of workload X509-SVIDs.
	SVIDs []*spiffex509.SVID

	// Roots is a set of X.509 root certificates, keyed by trust domain.
	Roots *spiffex509.Roots
}

// Default returns the default SVID (the first in the list).
//
// See the SPIFFE Workload API standard Section 5.3.
// (https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Workload_API.md#53-default-identity)
func (x *X509Context) Default() *spiffex509.SVID {
	return x.SVIDs[0]
}
