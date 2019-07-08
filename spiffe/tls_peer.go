package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"

	"github.com/spiffe/go-spiffe/internal"
	"github.com/spiffe/go-spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type TLSPeerOption func(*TLSPeer) error

// WithWorkloadAPIAddr overrides the address used to reach the SPIFFE Workload
// API. By default, the SPIFFE_ENDPOINT_SOCKET environment variable is used
// to convey the address.
func WithWorkloadAPIAddr(addr string) func(*TLSPeer) error {
	return func(p *TLSPeer) error {
		p.addr = addr
		return nil
	}
}

// WithLogger provides a logger to the TLSPeer
func WithLogger(log Logger) func(*TLSPeer) error {
	return func(p *TLSPeer) error {
		p.log = log
		return nil
	}
}

type TLSPeer struct {
	log    Logger
	addr   string
	client *workload.X509SVIDClient

	readyOnce sync.Once
	ready     chan struct{}

	mu    sync.RWMutex
	cert  *tls.Certificate
	roots map[string]*x509.CertPool
}

func NewTLSPeer(opts ...TLSPeerOption) (*TLSPeer, error) {
	p := &TLSPeer{
		ready: make(chan struct{}),
	}

	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, err
		}
	}

	if p.log == nil {
		p.log = nullLogger{}
	}

	var dialOpts []workload.DialOption
	if p.addr != "" {
		dialOpts = append(dialOpts, workload.WithAddr(p.addr))
	}

	client, err := workload.NewX509SVIDClient(&tlsPeerWatcher{p: p}, dialOpts...)
	if err != nil {
		return nil, err
	}
	client.Start()

	p.client = client
	return p, nil
}

func (p *TLSPeer) Close() error {
	return p.client.Stop()
}

func (p *TLSPeer) WaitUntilReady(ctx context.Context) error {
	select {
	case <-p.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *TLSPeer) GetCertificate() (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.cert == nil {
		return nil, errors.New("workload does not have a certificate yet")
	}
	return p.cert, nil
}

func (p *TLSPeer) GetRoots() (map[string]*x509.CertPool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.roots == nil {
		return nil, errors.New("workload does not have roots yet")
	}
	return p.roots, nil
}

func (p *TLSPeer) updateX509SVIDs(svids *workload.X509SVIDs) {
	p.log.Debugf("X509SVID workload API update received")

	// Use the default SVID for now
	// TODO: expand SVID selection options
	svid := svids.Default()
	_, trustDomainID, err := internal.GetIDsFromCertificate(svid.Certificates[0])
	if err != nil {
		p.onError(errors.New("unable to parse IDs from X509-SVID update"))
		return
	}

	cert := &tls.Certificate{
		Certificate: make([][]byte, 0, len(svid.Certificates)),
		PrivateKey:  svid.PrivateKey,
	}
	for _, svidCert := range svid.Certificates {
		cert.Certificate = append(cert.Certificate, svidCert.Raw)
	}

	roots := make(map[string]*x509.CertPool)
	for federatedDomainID, federatedDomainPool := range svid.FederatedTrustBundlePools {
		roots[federatedDomainID] = federatedDomainPool
	}
	roots[trustDomainID] = svid.TrustBundlePool

	p.mu.Lock()
	p.cert = cert
	p.roots = roots
	p.mu.Unlock()

	p.readyOnce.Do(func() {
		close(p.ready)
	})
}

func (p *TLSPeer) onError(err error) {
	p.log.Errorf("%v", err)
}

type tlsPeerWatcher struct {
	p *TLSPeer
}

func (w *tlsPeerWatcher) UpdateX509SVIDs(svids *workload.X509SVIDs) {
	w.p.updateX509SVIDs(svids)
}

func (w *tlsPeerWatcher) OnError(err error) {
	w.p.onError(err)
}

func (p *TLSPeer) Dial(ctx context.Context, network, address string, expectPeer ExpectPeerFunc) (net.Conn, error) {
	conn, err := new(net.Dialer).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	config, err := p.GetConfig(ctx, expectPeer)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return tls.Client(conn, config), nil
}

func (p *TLSPeer) Listen(ctx context.Context, network, address string, expectPeer ExpectPeerFunc) (net.Listener, error) {
	inner, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	l, err := p.NewListener(ctx, inner, expectPeer)
	if err != nil {
		inner.Close()
		return nil, err
	}

	return l, nil
}

func (p *TLSPeer) NewListener(ctx context.Context, inner net.Listener, expectPeer ExpectPeerFunc) (net.Listener, error) {
	config, err := p.GetConfig(ctx, expectPeer)
	if err != nil {
		return nil, err
	}

	return &peerTLSListener{
		Listener: inner,
		config:   config,
	}, nil
}

func (p *TLSPeer) GetConfig(ctx context.Context, expectPeer ExpectPeerFunc) (*tls.Config, error) {
	if expectPeer == nil {
		return nil, errors.New("authorize callback is required")
	}
	if err := p.WaitUntilReady(ctx); err != nil {
		return nil, err
	}
	return &tls.Config{
		ClientAuth:            tls.RequireAnyClientCert,
		InsecureSkipVerify:    true,
		GetCertificate:        AdaptGetCertificate(p),
		GetClientCertificate:  AdaptGetClientCertificate(p),
		VerifyPeerCertificate: AdaptVerifyPeerCertificate(p, expectPeer),
	}, nil
}

func AdaptGetCertificate(p *TLSPeer) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return p.GetCertificate()
	}
}

func AdaptGetClientCertificate(p *TLSPeer) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return p.GetCertificate()
	}
}

func AdaptVerifyPeerCertificate(p *TLSPeer, expectPeer ExpectPeerFunc) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var certs []*x509.Certificate
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}

		roots, err := p.GetRoots()
		if err != nil {
			return err
		}
		if _, err := VerifyPeerCertificate(certs, roots, expectPeer); err != nil {
			return err
		}
		return nil
	}
}

func (p *TLSPeer) DialGRPC(ctx context.Context, addr string, expectPeer ExpectPeerFunc, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	config, err := p.GetConfig(ctx, expectPeer)
	if err != nil {
		return nil, err
	}
	return grpc.DialContext(ctx, addr, append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(config)),
	}, opts...)...)
}

func ListenTLS(ctx context.Context, network, addr string, expectPeer ExpectPeerFunc) (net.Listener, error) {
	tlsPeer, err := NewTLSPeer()
	if err != nil {
		return nil, err
	}

	listener, err := tlsPeer.Listen(ctx, network, addr, expectPeer)
	if err != nil {
		tlsPeer.Close()
		return nil, err
	}

	return &tlsListener{
		Listener: listener,
		tlsPeer:  tlsPeer,
	}, nil
}

func DialTLS(ctx context.Context, network, addr string, expectPeer ExpectPeerFunc) (net.Conn, error) {
	tlsPeer, err := NewTLSPeer()
	if err != nil {
		return nil, err
	}
	defer tlsPeer.Close()
	return tlsPeer.Dial(ctx, network, addr, expectPeer)
}

type peerTLSListener struct {
	net.Listener
	config *tls.Config
}

func (l *peerTLSListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(c, l.config), nil
}

type tlsListener struct {
	net.Listener
	tlsPeer *TLSPeer
}

func (l *tlsListener) Close() error {
	err1 := l.tlsPeer.Close()
	err2 := l.Listener.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
