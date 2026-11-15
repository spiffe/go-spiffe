package brokerapi

import (
	"context"
	"errors"
	"fmt"

	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
)

// Client is a SPIFFE Broker API client.
//
// A Client owns a single gRPC connection to the Broker API. Sources created
// from the Client share that connection. gRPC transparently reconnects the
// connection as needed; individual streams are re-established by the sources
// when they are terminated.
//
// By default, the Client creates a Workload API X.509 source and uses it to
// build the mutual TLS credentials required by the Broker API. The source is
// closed when the Client is closed. The Broker API server X509-SVID is
// authorized by the Authorizer provided to New.
//
// Experimental: subject to change.
type Client struct {
	conn        *grpc.ClientConn
	apiClient   brokerpb.APIClient
	config      clientConfig
	ownedSource *workloadapi.X509Source
}

// New creates a new Client for the SPIFFE Broker API. The client should be
// closed when no longer in use to free underlying resources. The authorizer is
// used to authenticate the Broker API server X509-SVID. Callers that only need
// to match the server SPIFFE ID can use tlsconfig.AdaptMatcher.
//
// If no address is provided with WithAddr, the address in the
// SPIFFE_BROKER_SOCKET environment variable is used.
//
// If no transport credentials are provided with WithTransportCredentials,
// mTLS credentials are created from the source provided by WithMTLSSource or,
// if unset, from a new Workload API X.509 source.
//
// Experimental: subject to change.
func New(ctx context.Context, authorizer tlsconfig.Authorizer, options ...ClientOption) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if authorizer == nil {
		return nil, errors.New("brokerapi: authorizer is required")
	}

	config := defaultClientConfig()
	for _, option := range options {
		option.configureClient(&config)
	}

	if config.address == "" {
		var ok bool
		config.address, ok = GetDefaultAddress()
		if !ok {
			return nil, errors.New("brokerapi: address is not configured")
		}
	}

	target, err := TargetFromAddress(config.address)
	if err != nil {
		return nil, fmt.Errorf("brokerapi: invalid address: %w", err)
	}

	if config.credentials != nil && config.mtlsSource != nil {
		return nil, errors.New("brokerapi: cannot use both transport credentials and an X.509 source")
	}

	var ownedSource *workloadapi.X509Source
	if config.credentials == nil {
		var source MTLSSource
		if config.mtlsSource != nil {
			source = config.mtlsSource
		} else {
			ownedSource, err = workloadapi.NewX509Source(ctx, config.workloadAPISourceOptions...)
			if err != nil {
				return nil, fmt.Errorf("brokerapi: failed to create X.509 source: %w", err)
			}
			source = ownedSource
		}
		config.credentials = grpccredentials.MTLSClientCredentials(source, source, authorizer)
	}

	dialOptions := make([]grpc.DialOption, 0, len(config.dialOptions)+1)
	dialOptions = append(dialOptions, config.dialOptions...)
	dialOptions = append(dialOptions, grpc.WithTransportCredentials(config.credentials))

	conn, err := grpc.NewClient(target, dialOptions...)
	if err != nil {
		if ownedSource != nil {
			err = errors.Join(err, ownedSource.Close())
		}
		return nil, fmt.Errorf("brokerapi: failed to create client: %w", err)
	}

	return &Client{
		conn:        conn,
		apiClient:   brokerpb.NewAPIClient(conn),
		config:      config,
		ownedSource: ownedSource,
	}, nil
}

// Close closes the client and its underlying connection.
//
// Experimental: subject to change.
func (c *Client) Close() error {
	var errs []error
	if c.conn != nil {
		errs = append(errs, c.conn.Close())
	}
	if c.ownedSource != nil {
		errs = append(errs, c.ownedSource.Close())
	}
	return errors.Join(errs...)
}

func validateClient(client *Client) error {
	if client == nil || client.apiClient == nil {
		return errors.New("brokerapi: client is required")
	}
	return nil
}
