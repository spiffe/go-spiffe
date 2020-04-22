package test

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

type CA struct {
	tb     testing.TB
	parent *CA
	cert   *x509.Certificate
	key    crypto.Signer
}

type CertificateOption interface {
	apply(*x509.Certificate)
}

type certificateOption func(*x509.Certificate)

func (co certificateOption) apply(c *x509.Certificate) {
	co(c)
}

func NewCA(tb testing.TB, options ...CertificateOption) *CA {
	cert, key := CreateCACertificate(tb, nil, nil, options...)
	return &CA{
		tb:   tb,
		cert: cert,
		key:  key,
	}
}

func (ca *CA) ChildCA(options ...CertificateOption) *CA {
	cert, key := CreateCACertificate(ca.tb, ca.cert, ca.key, options...)
	return &CA{
		tb:     ca.tb,
		parent: ca,
		cert:   cert,
		key:    key,
	}
}

func (ca *CA) CreateX509SVID(spiffeID string, options ...CertificateOption) ([]*x509.Certificate, crypto.Signer) {
	cert, key := CreateX509SVID(ca.tb, ca.cert, ca.key, spiffeID, options...)
	return append([]*x509.Certificate{cert}, ca.chain(false)...), key
}

func (ca *CA) Roots() []*x509.Certificate {
	root := ca
	for root.parent != nil {
		root = root.parent
	}
	return []*x509.Certificate{root.cert}
}

func (ca *CA) Bundle(td spiffeid.TrustDomain) *x509bundle.Bundle {
	bundle := x509bundle.New(td)
	for _, root := range ca.Roots() {
		bundle.AddX509Root(root)
	}
	return bundle
}

func CreateCACertificate(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, options ...CertificateOption) (*x509.Certificate, crypto.Signer) {
	now := time.Now()
	serial := NewSerial(tb)
	key := NewEC256Key(tb)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("CA %x", serial),
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
	}

	applyOptions(tmpl, options...)

	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateX509Certificate(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, options ...CertificateOption) (*x509.Certificate, crypto.Signer) {
	now := time.Now()
	serial := NewSerial(tb)
	key := NewEC256Key(tb)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("X509-Certificate %x", serial),
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	}

	applyOptions(tmpl, options...)

	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateX509SVID(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, spiffeID string, options ...CertificateOption) (*x509.Certificate, crypto.Signer) {
	uriSAN, err := url.Parse(spiffeID)
	require.NoError(tb, err)

	serial := NewSerial(tb)
	options = append(options,
		WithSerial(serial),
		WithSubject(pkix.Name{
			CommonName: fmt.Sprintf("X509-SVID %x", serial),
		}),
		WithURIs([]*url.URL{uriSAN}))

	return CreateX509Certificate(tb, parent, parentKey, options...)
}

func CreateCertificate(tb testing.TB, tmpl, parent *x509.Certificate, pub, priv interface{}) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	require.NoError(tb, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(tb, err)
	return cert
}

func CreateWebCredentials(t testing.TB) (*x509.CertPool, *tls.Certificate) {
	ipaddresses := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

	rootCert, rootKey := CreateCACertificate(t, nil, nil,
		WithIPAddresses(ipaddresses))

	childCert, childKey := CreateX509Certificate(t, rootCert, rootKey,
		WithIPAddresses(ipaddresses))

	return x509util.NewCertPool([]*x509.Certificate{rootCert}),
		&tls.Certificate{
			Certificate: [][]byte{childCert.Raw},
			PrivateKey:  childKey,
		}
}

func NewSerial(tb testing.TB) *big.Int {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(tb, err)
	return new(big.Int).SetBytes(b)
}

func WithSerial(serial *big.Int) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.SerialNumber = serial
	})
}

func WithLifetime(notBefore, notAfter time.Time) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.NotBefore = notBefore
		c.NotAfter = notAfter
	})
}

func WithIPAddresses(ips []net.IP) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.IPAddresses = ips
	})
}

func WithURIs(uris []*url.URL) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.URIs = uris
	})
}

func WithSubject(subject pkix.Name) CertificateOption {
	return certificateOption(func(c *x509.Certificate) {
		c.Subject = subject
	})
}

func applyOptions(c *x509.Certificate, options ...CertificateOption) {
	for _, opt := range options {
		opt.apply(c)
	}
}

func (ca *CA) chain(includeRoot bool) []*x509.Certificate {
	chain := []*x509.Certificate{}
	next := ca
	for next != nil {
		if includeRoot || next.parent != nil {
			chain = append(chain, next.cert)
		}
		next = next.parent
	}
	return chain
}
