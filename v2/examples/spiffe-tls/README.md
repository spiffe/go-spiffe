# Mutual TLS Example

This example shows how two services can communicate using mTLS with X.509 SVIDs obtained from the SPIFFE Workload API. 

One of the workloads acts as a client and the other as the server. The use the SPIRE default socket path: `/tmp/agent.sock`. This value can also be set via the `SPIFFE_ENDOINT_SOCKET` environment variable.

The **server workload** creates a listener using the [spiffetls.Listen](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls?tab=doc#Listen) function.
It uses [spiffetls.MTLSServerWithSourceOptions](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls?tab=doc#MTLSServerWithSourceOptions) to configure  the source, and validates that clients present an X509-SVID with an expected SPIFFE ID.

```go
listener, err := spiffetls.ListenWithMode(ctx, "tcp", serverAddress,
    spiffetls.MTLSServerWithSourceOptions(
        tlsconfig.AuthorizeID(clientID),
        workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
    ))
```

Alternatively, the listener can use the `SPIFFE_ENDPOINT_SOCKET` environment variable to locate the Workload API.

```go
listener, err := spiffetls.Listen(context.Background(), "tcp", serverAddress, tlsconfig.AuthorizeID(spiffeID))
```

On the other side, the **client workload** dials the server using the [spiffetls.Dial](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls?tab=doc#Dial) function. 
It uses [spiffetls.MTLSClientWithSourceOptions](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls?tab=doc#MTLSClientWithSourceOptions) to configure the source with the Workload API address, and validates that the server X509-SVID has the expected SPIFFE ID.

```go
conn, err := spiffetls.DialWithMode(ctx, "tcp", serverAddress,
    spiffetls.MTLSClientWithSourceOptions(
        tlsconfig.AuthorizeID(spiffeID),
        workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
    ))
```

As with Listen, Dial can also use the `SPIFFE_ENDPOINT_SOCKET` environment variable to locate the Workload API

```go
conn, err := spiffetls.Dial(ctx, "tcp", serverAddress, tlsconfig.AuthorizeID(spiffeID))
``` 

The [tlsconfig.Authorizer](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#Authorizer) is used to authorize the mTLS peer. In this example, both the client and server use it to authorize the specific SPIFFE ID of the other side of the connection.

That is it! The go-spiffe library fetches and automatically renews the X.509 SVIDs of both workloads from the Workload API provider (i.e. SPIRE).

As soon as the mTLS connection is established, the client sends a message to the server and gets a response.


## Building
Build the client workload:
```bash
cd examples/spiffe-mTLS/client
go build
```

Build the server workload:
```bash
cd examples/spiffe-mTLS/server
go build
```

## Running
This example assumes the following preconditions:
- There is a SPIRE server and agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`
- The agent SPIFFE ID is `spiffe://example.org/host`.
- There is a `server-workload` and `client-workload` user in the system.

### 1. Create the registration entries
Create the registration entries for the client and server workloads:

Server:
```bash
./spire-server entry create -spiffeID spiffe://example.org/server \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:server-workload
```

Client: 
```bash
./spire-server entry create -spiffeID spiffe://example.org/client \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:client-workload
```

### 2. Start the server
Start the server with the `server-workload` user:
```bash
sudo -u server-workload ./server
```

### 3. Run the client
Run the client with the `client-workload` user:
```bash
sudo -u client-workload ./client
```

The server should have got a _"Hello server"_ message and responded with a _"Hello client"_ message.

If either workload encounters a peer with a different SPIFFE ID, they will abort the TLS handshake and the connection will fail. 
 
```
sudo -u server-workload ./client

Unable to read server response: remote error: tls: bad certificate
```

And the server log shows:
```
Error reading incoming data: unexpected ID "spiffe://example.org/server"
```
