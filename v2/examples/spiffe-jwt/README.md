# HTTP over TLS with JWT

This example shows how two services using HTTP can communicate using TLS with the server presenting an X509 SVID and expecting a client to authenticate with a JWT-SVID. The SVIDs are retrieved, and authentication is accomplished, via the SPIFFE Workload API.

The **HTTP server** creates a [workloadapi.X509Source](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi?tab=doc#X509Source).

```go
source, err := workloadapi.NewX509Source(ctx, clientOptions)
```

The socket path is provided as a client option. If the socket path is not provided, the value from the `SPIFFE_ENDPOINT_SOCKET` environment variable is used.

```go
source, err := workloadapi.NewX509Source(ctx)
```

The **HTTP server** then uses [workloadapi.X509Source](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi?tab=doc#X509Source) to create a `tls.Config` for TLS that will present the server X509-SVID.

The `tls.Config` is used when creating the HTTP server.

```go
tlsConfig := tlsconfig.TLSServerConfig(source)

server := &http.Server{
    Addr:      ":8443",
    TLSConfig: tlsConfig,
}
```

The server creates a JWTSource to obtain up-to-date JWT bundles from the Workload API.

```go
jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
```

A middleware is added to authenticate client JWT-SVIDs provided in the `Authorization` header.
This middleware validates the token using the [jwtsvid.ParseAndValidate](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/svid/jwtsvid?tab=doc#ParseAndValidate) using bundles obtained from the JWTSource.

```go
svid, err := jwtsvid.ParseAndValidate(token, a.jwtSource, a.audiences)
```

As an alternative to verifying the JWT-SVIDs directly, the Workload API can also be used:

```go
client, err := workloadapi.New(ctx)
if err != nil {
	log.Fatalf("Unable to connect to Workload API: %v", err)
}
svid, err := client.ValidateJWTSVID(ctx, token, audiences[0])
```

On the other side, the **HTTP client** uses the [workloadapi.X509Source](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi?tab=doc#X509Source) to create a `tls.Config` for TLS that authenticates the server certificate and verifies that it has the SPIFFE ID `spiffe://examples.org/server`. 

```go
serverID := spiffeid.RequireFromString("spiffe://example.org/server")
tlsConfig := tlsconfig.TLSClientConfig(source, tlsconfig.AuthorizeID(serverID))

client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: tlsConfig,
    },
}
```

The client fetches a JWT-SVID from the Workload API (via the JWTSource) and adds it as a bearer token in the `Authorization` header.

```go
svid, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
	Audience: audience,
})
if err != nil {
    log.Fatalf("Unable to fetch SVID: %v", err)
}
req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", svid.Marshal()))
```

That is it! The go-spiffe library fetches and automatically renews the X.509 SVID for the server and validates the client JWT SVIDs using the Workload API.

As soon as the TLS connection is established, the client sends an HTTP request to the server and gets a response.

## Building
Build the client workload:
```bash
cd examples/spiffe-jwt/client
go build
```

Build the server workload:
```bash
cd examples/spiffe-jwt/server
go build
```

## Running
This example assumes the following preconditions:
- There is a SPIRE Server and Agent up and running.
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

The server should display a log `Request received` and client `Success!!!`

To demonstrate a failure, an alternate audience value can be used. The server is expecting its own SPIFFE ID as the audience value and will reject the token if it doesn't match.

```
sudo -u client-workload ./client spiffe://example.org/some-other-server

Unauthorized
```

When the token is rejected, the server log shows:

```
Invalid token: jwtsvid: expected audience in ["spiffe://example.org/server"] (audience=["spiffe://example.org/some-other-server"])
```
