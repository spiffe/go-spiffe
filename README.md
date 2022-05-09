#  go-spiffe (v2)

This library is a convenient Go library for working with [SPIFFE](https://spiffe.io/).

It leverages the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md), providing high level functionality that includes:
* Establishing mutually authenticated TLS (__mTLS__) between workloads powered by SPIFFE.
* Obtaining and validating [X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md) and [JWT-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md).
* Federating trust between trust domains using [SPIFFE bundles](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#3-spiffe-bundles).
* Bundle management.

## Documentation

See the [Go Package](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2) documentation.

## Quick Start

Prerequisites:
1. Running [SPIRE](https://spiffe.io/spire/) or another SPIFFE Workload API
   implementation.
2. `SPIFFE_ENDPOINT_SOCKET` environment variable set to address of the Workload
   API (e.g. `unix:///tmp/agent.sock`). Alternatively the socket address can be
   provided programatically.

To create an mTLS server:

```go
listener, err := spiffetls.Listen(ctx, "tcp", "127.0.0.1:8443", tlsconfig.AuthorizeAny())
```

To dial an mTLS server:

```go
conn, err := spiffetls.Dial(ctx, "tcp", "127.0.0.1:8443", tlsconfig.AuthorizeAny())
```

The client and server obtain
[X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
and X.509 bundles from the [SPIFFE Workload
API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
The X509-SVIDs are presented by each peer and authenticated against the X.509
bundles. Both sides continue to be updated with X509-SVIDs and X.509 bundles
streamed from the Workload API (e.g. secret rotation).

## Examples

The [examples](./v2/examples) directory contains rich examples for a variety of circumstances.
