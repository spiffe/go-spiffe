# Authenticating Workloads over TLS-encrypted HTTP Connections Using JWT-SVIDs

This example shows how to use the go-spiffe library to make a server workload authenticate a client workload using JWT-SVIDs fetched from the Workload API. 

JWT-SVIDs are useful when the workloads are not able to establish an mTLS communication channel between each other. For instance, when the server workload is behind a TLS terminating load balancer or proxy, a client workload cannot be authenticated directly by the server via mTLS and X.509-SVID. So, an alternative is to forego authenticating the client at the load balancer or proxy and instead require that clients authenticate via SPIFFE JWT-SVIDs conveyed directly to the server via the application layer.

The scenario used in this example goes like this:
1. The server:
   - Creates an X509Source struct.
   - Creates a JWTSource struct.
   - Starts listening for HTTP requests over TLS. Only one resource is served at `/`.
2. The reverse proxy:
   - Creates an X509Source struct.
   - Starts listening for HTTP requests over TLS. It forwards requests to `/` only. 
3. The client:
   - Creates an X509Source struct.
   - Creates a JWTSource struct.
   - Fetches a JWT-SVID using the JWTSource.
   - Creates a `GET /` request with the JWT-SVID set as the value of the `Authorization` header.
   - Sends the request to the proxy using TLS authentication for establishing the connection. 
4. The proxy receives the request, logs the request's method and URL, and forwards the request to the server.
5. The server receives the request, extracts the JWT-SVID from the `Authorization` header, and verifies the token. If the token is valid, it logs `Request received` and returns a response with a body containing the string `Success!!!`, otherwise an `Unauthorized` HTTP code is returned.
6.  The proxy receives the response from the server and passes it to the client.
7.  The client receives the response. If the response has an HTTP 200 status, its body is logged, otherwise the HTTP status code is logged.

## Creating an X509Source struct
As you may noted, the three workloads create a [workloadapi.X509Source](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi?tab=doc#X509Source) struct.
```go
	x509Source, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
	)
```
Where:
- ctx is a `context.Context`. `NewX509Source` function blocks until the first Workload API response is received or this context times out or is cancelled.
- socketPath is the address of the Workload API (`unix:///tmp/agent.sock`) to which the internal Workload API client connects to get up-to-date SVIDs. Alternatively, we could have omitted this configuration option, in which case the listener would have used the `SPIFFE_ENDPOINT_SOCKET` environment variable to locate the Workload API. The code could have then been written like this:
```go
	x509Source, err := workloadapi.NewX509Source(ctx)
```
In all cases, the `X509Source` is used to create a `tls.Config` for the underlying transport connection of the HTTP client/server. However, there are some differences in its usage on the server, client, and proxy workloads: 

The **server workload** uses the `X509Source` to create the [TLSServerConfig](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#TLSServerConfig) for the HTTP server used:
```go
	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: tlsconfig.TLSServerConfig(x509Source),
	}
```
This enables the server to present an X.509-SVID to the other end of the connection. This SVID is provided by the `X509Source` via the Workload API.

The **client workload** uses the `X509Source` to create the [TLSClientConfig](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#TLSClientConfig) for the `Transport` of the HTTP client used:
```go
    serverID := spiffeid.RequireFromString("spiffe://example.org/server")
    .
    .
    .
    client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.TLSClientConfig(
				x509Source,
				tlsconfig.AuthorizeID(serverID),
			),
		},
	}
``` 
This enables the client to verify that the X.509-SVID presented by the other end of the connection has the specified SPIFFE ID by using:
- The trust bundle provided by the Workload API via the `X509Source`.
- The [Authorizer](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#Authorizer) returned by [tlsconfig.AuthorizeID()](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#AuthorizeID)

The **proxy workload** uses the `X509Source` to create the [TLSClientConfig](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#TLSClientConfig) for the `Transport` of the HTTP reverse proxy used:
```go
	proxy := httputil.NewSingleHostReverseProxy(remote)
	transport := *(http.DefaultTransport.(*http.Transport)) // copy of http.DefaultTransport.
	transport.TLSClientConfig = tlsconfig.TLSClientConfig(
		x509Source, tlsconfig.AuthorizeID(spiffeid.RequireFromString("spiffe://example.org/server")),
	)
	proxy.Transport = &transport
```
This enables the proxy to verify that the X.509-SVID presented by the server has the specified SPIFFE ID by using:
- The trust bundle provided by the Workload API via the `X509Source`.
- The [Authorizer](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#Authorizer) function returned by [tlsconfig.AuthorizeID()](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#AuthorizeID)

The **proxy workload** also uses the `X509Source` to create the [TLSServerConfig](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig?tab=doc#TLSServerConfig) for the HTTP server used:
```go
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsconfig.TLSServerConfig(x509Source),
	}
```
This enables the proxy to present an X.509-SVID to the client. This SVID is provided by the `X509Source` via the Workload API, and contains the SPIFFE ID of the server (as explained later in **Create the registration entries** section).

## Creating a JWTSource struct
On the scenario described we can see that only the client and the server workloads create a [workloadapi.JWTSource](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi?tab=doc#JWTSource). This is because the proxy workload doesn't need to deal with JWTs since the server is the one in charge of authenticating the clients:
```go
    jwtSource, err := workloadapi.NewJWTSource(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)),
	)
```
Where:
- ctx is a `context.Context`. `NewJWTSource` function blocks until the first Workload API response is received or this context times out or is cancelled.
- socketPath is the address of the Workload API (`unix:///tmp/agent.sock`) to which the internal Workload API client connects to get up-to-date SVIDs. Alternatively, we could have omitted this configuration option, in which case the listener would have used the `SPIFFE_ENDPOINT_SOCKET` environment variable to locate the Workload API. The code could have then been written like this:
```go
	jwtSource, err := workloadapi.NewJWTSource(ctx)
```
Although both client and server workloads create a `JWTSource`, it is used differently in each case:

The **client workload** uses the `JWTSource` to get a JWT-SVID by calling its [FetchJWTSVID](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi?tab=doc#JWTSource.FetchJWTSVID) function:
```go
	svid, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
```
Where:
- ctx is a `context.Context`. `FetchJWTSVID` method blocks until a response is received or this context times out or is cancelled.
- audience is the intended recipient of the JWT-SVID. By default it is `spiffe://example.org/server`, otherwise it is equal to the value passed as the first argument of the client's executable.

Then, the client uses the JWT-SVID to set a bearer token to the request's `Authorization` header:
```go
	req, err := http.NewRequest("GET", serverURL, nil)
	.
	.
	.
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", svid.Marshal()))
```

The **server workload** uses the `JWTSource` to authenticate the client by calling the [ParseAndValidate](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/svid/jwtsvid?tab=doc#ParseAndValidate) function:
```go
	_, err := jwtsvid.ParseAndValidate(token, a.jwtSource, a.audiences)
```
Where:
- token is the marshalled JWT-SVID sent by the client in the `Authorization` header.
- a.jwtSource is the `JWTSource`.
- a.audiences is a slice of strings. Specifies a list of expected audiences in the `aud` field of the token.

When `ParseAndValidate` returns an error, the server returns an `Unauthorized` status. Otherwise, the request continues normal processing.

## That is it!
As we can see the go-spiffe library allows your application avoiding to deal with the implementation details of the Workload API. You just create the SVID sources and then simply ask the library for what you need.

## Building
To build the client workload:
```bash
cd examples/spiffe-jwt-using-proxy/client
go build
```

To build the proxy workload:
```bash
cd examples/spiffe-jwt-using-proxy/proxy
go build
```

To build the server workload:
```bash
cd examples/spiffe-jwt-using-proxy/server
go build
```

## Running
This example assumes the following preconditions:
- There is a SPIRE Server and Agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`.
- The agent SPIFFE ID is `spiffe://example.org/host`.
- There are `server-workload` and `client-workload` users in the system.

### 1. Create the registration entries
Create two registration entries, one for the client workload and another for the server and proxy workloads:

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

We will use the `server-workload` user to run the proxy because we want it to be as transparent as possible to the client. By using this user, the proxy will get an SVID with the same SPIFFE ID as the server, due to the `unix:user:server-workload` selector used when registering the entry.

### 2. Start the server
Start the server with the `server-workload` user:
```bash
sudo -u server-workload ./server
```

### 3. Start the proxy
Start the proxy with the `server-workload` user:
```bash
sudo -u server-workload ./proxy
```

### 4. Run the client
Run the client with the `client-workload` user:
```bash
sudo -u client-workload ./client
```

For each component the logs would contain:  
| Component| Log content (stdout) |
|----------|----------------------|
| Proxy    | `GET /`              |
| Server   | `Request received`   |
| Client   | `Success!!!`         |

To demonstrate a failure, we can run the client using a wrong audience as the first argument:

```
sudo -u client-workload ./client spiffe://example.org/some-other-server

401 Unauthorized
```

Given that the server expects its own SPIFFE ID as the audience value it will reject the token because of the audience's mismatch. Then server log would contain:

```
Invalid token: jwtsvid: expected audience in ["spiffe://example.org/server"] (audience=["spiffe://example.org/some-other-server"])
```
