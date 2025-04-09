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

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

var localhostIPs = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

type CA struct {
	tb     testing.TB
	td     spiffeid.TrustDomain
	parent *CA
	cert   *x509.Certificate
	key    crypto.Signer
	jwtKey crypto.Signer
	jwtKid string
}

func NewCA(tb testing.TB, td spiffeid.TrustDomain) *CA {
	cert, key := CreateCACertificate(tb, nil, nil)
	return &CA{
		tb:     tb,
		td:     td,
		cert:   cert,
		key:    key,
		jwtKey: NewEC256Key(tb),
		jwtKid: NewKeyID(tb),
	}
}

func (ca *CA) ChildCA(options ...SVIDOption) *CA {
	cert, key := CreateCACertificate(ca.tb, ca.cert, ca.key, options...)
	return &CA{
		tb:     ca.tb,
		parent: ca,
		cert:   cert,
		key:    key,
		jwtKey: NewEC256Key(ca.tb),
		jwtKid: NewKeyID(ca.tb),
	}
}

func (ca *CA) CreateX509SVID(id spiffeid.ID, options ...SVIDOption) *x509svid.SVID {
	cert, key := CreateX509SVID(ca.tb, ca.cert, ca.key, id, options...)
	svid := &x509svid.SVID{
		ID:           id,
		Certificates: append([]*x509.Certificate{cert}, ca.chain(false)...),
		PrivateKey:   key,
	}
	applyX509SVIDOptions(svid, options...)
	return svid
}

func (ca *CA) CreateX509Certificate(options ...SVIDOption) ([]*x509.Certificate, crypto.Signer) {
	cert, key := CreateX509Certificate(ca.tb, ca.cert, ca.key, options...)
	return append([]*x509.Certificate{cert}, ca.chain(false)...), key
}

func (ca *CA) CreateJWTSVID(id spiffeid.ID, audience []string, options ...SVIDOption) *jwtsvid.SVID {
	claims := jwt.Claims{
		Subject:  id.String(),
		Issuer:   "FAKECA",
		Audience: audience,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(ca.jwtKey),
				KeyID: ca.jwtKid,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	require.NoError(ca.tb, err)

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).Serialize()
	require.NoError(ca.tb, err)

	svid, err := jwtsvid.ParseInsecure(signedToken, audience)
	require.NoError(ca.tb, err)

	applyJWTSVIDOptions(svid, options...)

	return svid
}

func (ca *CA) X509Authorities() []*x509.Certificate {
	root := ca
	for root.parent != nil {
		root = root.parent
	}
	return []*x509.Certificate{root.cert}
}

func (ca *CA) JWTAuthorities() map[string]crypto.PublicKey {
	return map[string]crypto.PublicKey{
		ca.jwtKid: ca.jwtKey.Public(),
	}
}

func (ca *CA) Bundle() *spiffebundle.Bundle {
	bundle := spiffebundle.New(ca.td)
	bundle.SetX509Authorities(ca.X509Authorities())
	bundle.SetJWTAuthorities(ca.JWTAuthorities())
	return bundle
}

func (ca *CA) X509Bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(ca.td, ca.X509Authorities())
}

func (ca *CA) JWTBundle() *jwtbundle.Bundle {
	return jwtbundle.FromJWTAuthorities(ca.td, ca.JWTAuthorities())
}

func CreateCACertificate(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, options ...SVIDOption) (*x509.Certificate, crypto.Signer) {
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

	applyCertOptions(tmpl, options...)

	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateX509Certificate(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, options ...SVIDOption) (*x509.Certificate, crypto.Signer) {
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
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	applyCertOptions(tmpl, options...)

	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateX509SVID(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, id spiffeid.ID, options ...SVIDOption) (*x509.Certificate, crypto.Signer) {
	serial := NewSerial(tb)
	options = append(options,
		WithSerial(serial),
		WithKeyUsage(x509.KeyUsageDigitalSignature),
		WithSubject(pkix.Name{
			CommonName: fmt.Sprintf("X509-SVID %x", serial),
		}),
		WithURIs(id.URL()))

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
	rootCert, rootKey := CreateCACertificate(t, nil, nil)

	childCert, childKey := CreateX509Certificate(t, rootCert, rootKey,
		WithIPAddresses(localhostIPs...))

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

type SVIDOption struct {
	certificateOption func(*x509.Certificate)
	x509SvidOption    func(*x509svid.SVID)
	jwtSvidOption     func(*jwtsvid.SVID)
}

func (s SVIDOption) applyJWTSVIDOption(svid *jwtsvid.SVID) {
	if s.jwtSvidOption != nil {
		s.jwtSvidOption(svid)
	}
}

func (s SVIDOption) applyCertOption(certificate *x509.Certificate) {
	if s.certificateOption != nil {
		s.certificateOption(certificate)
	}
}

func (s SVIDOption) applyX509SVIDOption(svid *x509svid.SVID) {
	if s.x509SvidOption != nil {
		s.x509SvidOption(svid)
	}
}

func WithSerial(serial *big.Int) SVIDOption {
	return SVIDOption{
		certificateOption: func(c *x509.Certificate) {
			c.SerialNumber = serial
		},
	}
}

func WithKeyUsage(keyUsage x509.KeyUsage) SVIDOption {
	return SVIDOption{
		certificateOption: func(c *x509.Certificate) {
			c.KeyUsage = keyUsage
		},
	}
}

func WithLifetime(notBefore, notAfter time.Time) SVIDOption {
	return SVIDOption{
		certificateOption: func(c *x509.Certificate) {
			c.NotBefore = notBefore
			c.NotAfter = notAfter
		},
	}
}

func WithIPAddresses(ips ...net.IP) SVIDOption {
	return SVIDOption{
		certificateOption: func(c *x509.Certificate) {
			c.IPAddresses = ips
		},
	}
}

func WithURIs(uris ...*url.URL) SVIDOption {
	return SVIDOption{
		certificateOption: func(c *x509.Certificate) {
			c.URIs = uris
		},
	}
}

func WithSubject(subject pkix.Name) SVIDOption {
	return SVIDOption{
		certificateOption: func(c *x509.Certificate) {
			c.Subject = subject
		},
	}
}

func WithHint(hint string) SVIDOption {
	return SVIDOption{
		x509SvidOption: func(svid *x509svid.SVID) {
			svid.Hint = hint
		},
		jwtSvidOption: func(svid *jwtsvid.SVID) {
			svid.Hint = hint
		},
	}
}

func applyCertOptions(c *x509.Certificate, options ...SVIDOption) {
	for _, opt := range options {
		opt.applyCertOption(c)
	}
}

func applyX509SVIDOptions(svid *x509svid.SVID, options ...SVIDOption) {
	for _, opt := range options {
		opt.applyX509SVIDOption(svid)
	}
}

func applyJWTSVIDOptions(svid *jwtsvid.SVID, options ...SVIDOption) {
	for _, opt := range options {
		opt.applyJWTSVIDOption(svid)
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
