# Deprecation Warning

__NOTE:__ The code samples in this directory were written for the [v1 version](../README.md) of the go-spiffe library, which will be deprecated soon.

We recommend that you write new code using the `v2` go-spiffe module. See [go-spiffe (v2) Examples](../v2/examples) for code samples written for the `v2` go-spiffe module. See [go-spiffe (v2)](../v2) for general information about the `v2` go-spiffe module.

# Examples

This section contains a set of standalone examples that demonstrate different use cases for the `v1` go-spiffe library.

## Use cases

- [SVIDs for mTLS connections](./svid-mTLS): _Get automatically rotated X.509 SVIDs for your workloads and use it to establish mTLS connections between them._

- [SVIDs stream](./svid-watcher): _Get automatically rotated X.509 SVIDs for your workload._

- [gRPC client](./svid-grpc-client): _Creates a gRPC SPIFFE client and access the different methods of the [Workload API](../proto/spiffe/workload/workload.proto)._
