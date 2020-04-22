# X.509 SVID Watcher example

This example shows how a service can obtain X.509 SVIDs and JWT Bundles from the SPIFFE workload API which are automatically rotated before expiration.

The first step is to create a workload API client. It implements different methods to query the SPIFFE Workload API. It takes a [workloadapi.ClientOption](../../workloadapi/option.go#L10) to create client.

```go
client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
```

In case `workloadapi.WithAddr` is not provided, the value of `SPIFFE_ENDPOINT_SOCKET` environment variable will be used 

```go
client, err := workloadapi.New(ctx)
```

The library provides a watcher interface type [workloadapi.X509ContextWatcher](../../workloadapi/client.go#L322) to manipulate responses when SVIDs rotations or errors.

The watcher for X.509 SVID is used in [workloadapi.WatchX509Context](../../workloadapi/client.go#L151) function.
```go
err = client.WatchX509Context(ctx, &x509Watcher{})
```
The watcher will be notifier every time an SVID is update or an error occurrs

It is possible to watch for JWT Bundles updates. The library provide a watcher interface type [workloadapi.JWTBundleWatcher](../../workloadapi/client.go#L333) to manipulate responses on JWT Bundles rotations or errors.

The watcher for JWT Bundles is used in  [workloadapi.WatchJWTBundles](../../workloadapi/client.go#L201) 
```go
err = client.WatchJWTBundles(ctx, &jwtWatcher{})
```

The watcher will be notified every time a JWT Bundle  is updated or an error occurs. 

## Building
Build the spiffe-watcher example:

```bash
cd examples/spiffe-watcher
go build
```

## Running
This example assumes the following preconditions:
- There are a SPIRE server and agent up and running.
- There is a Unix workload attestor configured.
- The trust domain is `example.org`
- The agent SPIFFE ID is `spiffe://example.org/host`.
- There is a `spiffe-watcher` user in the system.

### 1. Create the registration entry
Create the registration entry for the spiffe-watcher workload:
```bash
./spire-server entry create -spiffeID spiffe://example.org/spiffe-watcher \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:spiffe-watcher
```

### 2. Start the workload
Start the spiffe-watcher with the `spiffe-watcher` user:
```bash
sudo -u spiffe-watcher ./spiffe-watcher
```

The watcher prints the SVID SPIFFE ID every time an SVID is updated.
 
```
SVID updated for "spiffe://example.org/spiffe-watcher":
-----BEGIN CERTIFICATE-----
MIIB5TCCAYugAwIBAgIRAIkzRMvOixmAvYiJwow5AOUwCgYIKoZIzj0EAwIwHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBlNQSUZGRTAeFw0yMDA0MjIxNjA2MjJaFw0y
MDA0MjIxNzA2MzJaMB0xCzAJBgNVBAYTAlVTMQ4wDAYDVQQKEwVTUElSRTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABISDihEjzQNw0lBVmG6N8g1dSxA5qZpd5Xyb
ilpilnmmZZsCXz3LkShtk3Jem7TfTDcpAVNWEApz4whSm78ICwOjgaowgacwDgYD
VR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNV
HRMBAf8EAjAAMB0GA1UdDgQWBBSEyoGr5Y9bdpNedAwpxW9O6zBDmzAfBgNVHSME
GDAWgBTLGktJw00mGe07dUGY6JQkyghF3TAoBgNVHREEITAfhh1zcGlmZmU6Ly9l
eGFtcGxlLm9yZy93b3JrbG9hZDAKBggqhkjOPQQDAgNIADBFAiEAnOqqI+fKDPQn
QVgh01bmWy00DNWWYpKuAQakj9zk4PMCIDsNbYwEztgxlsb1DxZlqJpR2gZkdoAJ
FnFdqZr2XMrT
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB4TCCAWegAwIBAgIRAP/k5B666y4MrrdwssWL6rUwCgYIKoZIzj0EAwMwHjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBlNQSUZGRTAeFw0yMDA0MjIxNDM3NTBaFw0y
MDA0MjMxNDM4MDBaMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKEwZTUElGRkUwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAARleC9KdQcH05tTgYfihasPGxeeo1kXztL4
1Th5vUF2D0In7kCcwZu3o9m9mguiJ4aeTFXL5QVU0ju6GiCdFXH/o4GFMIGCMA4G
A1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLGktJw00m
Ge07dUGY6JQkyghF3TAfBgNVHSMEGDAWgBSHpfNXovA1rMD4ZMRU527TujnI6DAf
BgNVHREEGDAWhhRzcGlmZmU6Ly9leGFtcGxlLm9yZzAKBggqhkjOPQQDAwNoADBl
AjArmjEf1aHXvqfy9pOC+7ZKon22x1FV4tHbNWuRvPZEyy86cDCkU6uaBgjJ3GKR
+gcCMQDMoTlCekCTdCfHeQOy7kbr5fjXFiw0+SnO/4iFGBLnrDcnIIpxCdzKL4HW
gLI5JLc=
-----END CERTIFICATE-----

jwt bundle updated "example.org": {"keys":[{"kty":"EC","kid":"KULvTqUAs9SwuYGoO06ifavOQkA5Dkic","crv":"P-256","x":"WtHZ13-FO_B4SXhYbtXE-e7TmFl_txMOtY-Ls3jWPeE","y":"UNkGvC4MYOUXbgoHRCXGAtSTVE9zqXCkecjTB2cj9RA"}]}
jwt bundle updated "example.org": {"keys":[{"kty":"EC","kid":"KULvTqUAs9SwuYGoO06ifavOQkA5Dkic","
```


