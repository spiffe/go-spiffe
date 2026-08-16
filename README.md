#  go-spiffe (v2)

This library is a convenient Go library for working with [SPIFFE](https://spiffe.io/).

It leverages the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md), providing high level functionality that includes:
* Establishing mutually authenticated TLS (__mTLS__) between workloads powered by SPIFFE.
* Obtaining and validating [X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md) and [JWT-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md).
* Federating trust between trust domains using [SPIFFE bundles](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#3-spiffe-bundles).
* Bundle management.

## Documentation

See the [Go Package](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2) documentation.

## Which module should I use?

This repository hosts two Go modules:

| Module | Import path | Depends on |
| --- | --- | --- |
| Full | `github.com/spiffe/go-spiffe/v2` | gRPC, protobuf, go-jose |
| Lite | `github.com/spiffe/go-spiffe/lite` | go-jose |

`lite` holds the SPIFFE types and logic that need no gRPC: SPIFFE ID and trust
domain parsing, X.509/JWT/SPIFFE bundles, X509-SVIDs and JWT-SVIDs, TLS config
construction, and federation. Reach for it when your workload receives its
identity some way other than the Workload API — for example from files — and you
would rather not take on the gRPC dependency tree.

The `v2` module is the full library. It adds the [SPIFFE Workload
API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
client, `spiffetls`, and the gRPC credentials helpers on top of `lite`, and
re-exports every `lite` symbol at its original `v2` import path. Existing code
importing `github.com/spiffe/go-spiffe/v2/...` needs no changes.

Moving from `v2` to `lite` is an import path rewrite, since the package layout is
the same:

```
github.com/spiffe/go-spiffe/v2/spiffeid  ->  github.com/spiffe/go-spiffe/lite/spiffeid
```

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

The [examples](./examples) directory contains rich examples for a variety of circumstances.

## Supported Go Versions

This library tracks the minimum officially supported Go version (i.e. N-1). The
only exception to this policy will be in response to a security issue affecting
a dependency that forces a premature upgrade. This action is expected to be rare, 
will not be taken lightly, and not until reasonable efforts to mitigate the
security issue while maintaining this policy are pursued.

## Reporting Security Vulnerabilities

If you've found a vulnerability or a potential vulnerability in go-spiffe, please let us know at <security@spiffe.io>. We'll send a confirmation email to acknowledge your report, and we'll send an additional email when we've identified the issue positively or negatively.
