package spiffex509

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type Roots struct{}

func NewRoots() *Roots {
	panic("not implemented")
}

func (r *Roots) Insert(trustDomain spiffeid.TrustDomain, rootCerts []*x509.Certificate) {
	panic("not implemented")
}

func (r *Roots) Remove(trustDomain spiffeid.TrustDomain) bool {
	panic("not implemented")
}

func (r *Roots) Has(trustDomain spiffeid.TrustDomain) bool {
	panic("not implemented")
}

func (r Roots) GetX509RootsForTrustDomain(trustDomain spiffeid.TrustDomain) ([]*x509.Certificate, error) {
	panic("not implemented")
}
