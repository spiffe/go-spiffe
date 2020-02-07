package spiffegrpc

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffejwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type JWTSVIDFetcher interface {
	FetchX509SVID(ctx context.Context, uris ...string) (*spiffejwt.SVID, error)
}

type JWTSVIDFetcherFunc func(ctx context.Context, uris ...string) (*spiffejwt.SVID, error)

func (fn JWTSVIDFetcherFunc) FetchX509SVID(ctx context.Context, uris ...string) (*spiffejwt.SVID, error) {
	return fn(ctx, uris...)
}

func JWTSVIDPerRPCCredentials(fetcher JWTSVIDFetcher) credentials.PerRPCCredentials {
	panic("not implemented")
}

func JWTSVIDUnaryServerInterceptor(source spiffejwt.KeyStore, validator spiffejwt.Validator, audience string, audiences ...string) grpc.UnaryServerInterceptor {
	panic("not implemented")
}

func JWTSVIDStreamServerInterceptor(source spiffejwt.KeyStore, validator spiffejwt.Validator, audience string, audiences ...string) grpc.StreamServerInterceptor {
	panic("not implemented")
}
