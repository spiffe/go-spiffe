# Deprecation Warning

__NOTE:__ This version of the library will be deprecated soon.

The [v2](./v2) module is in **beta** and published under
`github.com/spiffe/go-spiffe/v2`, following go module guidelines.

**New code should strongly consider using the `v2` module.**

See the [v2 README](./v2) for more details.

# go-spiffe (v1) library [![GoDoc](https://godoc.org/github.com/spiffe/go-spiffe?status.svg)](https://godoc.org/github.com/spiffe/go-spiffe)

## Overview

The go-spiffe project provides two components:
- a command-line utility to parse and verify SPIFFE
identities encoded in X.509 certificates as described in the
[SPIFFE Standards](https://github.com/spiffe/spiffe/tree/master/standards).
- a client library that provides an interface to the SPIFFE Workload API.

## Installing it
```shell
go get -u -v github.com/spiffe/go-spiffe
```

## Importing it in your Go code

See the [examples](./examples) or visit the [documentation](https://pkg.go.dev/github.com/spiffe/go-spiffe) for more information.

## Installing the command line interface
The command line interface can be used to retrieve and view URIs stored
in the SAN extension of certificates

```shell
go get -u -v github.com/spiffe/go-spiffe/cmd/spiffe
spiffe testdata/leaf.cert.pem $HOME/certs/proj.pem
Path:: #1: "testdata/leaf.cert.pem"
  URI #1: "spiffe://dev.acme.com/path/service"
```
