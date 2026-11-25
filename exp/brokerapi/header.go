package brokerapi

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const brokerMetadataKey = "broker.spiffe.io"

func unaryMetadataInterceptor(
	ctx context.Context,
	method string,
	req any,
	reply any,
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	ctx = metadata.AppendToOutgoingContext(ctx, brokerMetadataKey, "true")
	return invoker(ctx, method, req, reply, cc, opts...)
}

func streamMetadataInterceptor(
	ctx context.Context,
	desc *grpc.StreamDesc,
	cc *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, brokerMetadataKey, "true")
	return streamer(ctx, desc, cc, method, opts...)
}
