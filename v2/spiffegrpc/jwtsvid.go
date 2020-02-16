package spiffegrpc

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffejwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// JWTSVIDFetcher is used to fetch a JWT-SVID. It is used to provide per-RPC
// JWT-SVID credentials.
type JWTSVIDFetcher interface {
	// FetchJWTSVID fetches a JWT-SVID. The endpoint URIs are provided as metadata
	// to help the implementor decide the claims of the JWT-SVID (e.g. audience)
	FetchJWTSVID(ctx context.Context, uris ...string) (*spiffejwt.SVID, error)
}

// JWTSVIDFetcherFunc is a convenience type for implementing JWTSVIDFetcher
// with a function.
type JWTSVIDFetcherFunc func(ctx context.Context, uris ...string) (*spiffejwt.SVID, error)

// FetchJWTSVID fetches a JWT-SVID. The endpoint URIs are provided as metadata
// to help the implementor decide the claims of the JWT-SVID (e.g. audience)
func (fn JWTSVIDFetcherFunc) FetchJWTSVID(ctx context.Context, uris ...string) (*spiffejwt.SVID, error) {
	return fn(ctx, uris...)
}

// JWTSVIDPerRPCCredentials returns a PerRPCCredentials implementation for use
// with grpc.WithPerRPCCredentials or grpc.PerRPCCredentials.
func JWTSVIDPerRPCCredentials(fetcher JWTSVIDFetcher) credentials.PerRPCCredentials {
	panic("not implemented")
}

// JWTSVIDUnaryServerInterceptor implements a unary server interceptor that
// verifies and validates the incoming JWT-SVIDs using the given key store,
// validator, and audience values.
func JWTSVIDUnaryServerInterceptor(source spiffejwt.KeyStore, validator spiffejwt.Validator, audience string, audiences ...string) grpc.UnaryServerInterceptor {
	panic("not implemented")
}

// JWTSVIDStreamServerInterceptor implements a stream server interceptor that
// verifies and validates the incoming JWT-SVIDs using the given key store,
// validator, and audience values.
func JWTSVIDStreamServerInterceptor(source spiffejwt.KeyStore, validator spiffejwt.Validator, audience string, audiences ...string) grpc.StreamServerInterceptor {
	panic("not implemented")
}
