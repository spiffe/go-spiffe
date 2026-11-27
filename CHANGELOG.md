# Changelog

## [2.10.0] - 2026-11-27

### Added

- Experimental `exp/witwpt` package, which mints Workload Proof Tokens (WPTs) bound to a WIT-SVID and a request target (#415)
- Support for ML-DSA keys in X509-SVIDs, JWT-SVIDs, WIT-SVIDs and bundles. ML-DSA support requires building with Go 1.27 or later. With earlier Go versions, ML-DSA keys in bundles are ignored (#440)
- `federation.WithSlogger` and `workloadapi.WithSlogger` options to log through a `*slog.Logger` (#449)
- `tlsconfig.VerifyConnection` and `tlsconfig.WrapVerifyConnection`, which verify and authorize the peer X509-SVID on every handshake, including resumed sessions (#447)
- Custom claims on WIT-SVIDs are now available through the `Claims` field of `witsvid.SVID` (#410)
- `GetWITSVID` method on `workloadapi.WITSource`, which returns the default WIT-SVID (#410)

### Changed

- Minimum Go version is now go1.26.0, following our support policy (#440, #447)
- The `tlsconfig` Hook functions that verify the peer X509-SVID (`HookTLSClientConfig`, `HookMTLSClientConfig`, `HookMTLSServerConfig` and `HookMTLSWebServerConfig`) now also set `VerifyConnection`, and the two server ones also set `WrapSession` and `UnwrapSession`. Existing callbacks are wrapped, so they must be set before hooking, and a configuration should be hooked only once. Session ticket keys must be set on the hooked configuration (#447)
- `spiffetls.WithDialTLSConfigBase` and `spiffetls.WithListenTLSConfigBase` now clone the base TLS configuration instead of modifying it (#447)
- `jwtsvid.ParseAndValidate` and `jwtsvid.ParseInsecure` now reject tokens with a missing `aud` claim or an empty `aud` value (#442)
- Bundle marshaling in `bundle/jwtbundle`, `bundle/spiffebundle` and `exp/bundle/witbundle` is now deterministic, with JWT and WIT authorities emitted in sorted key ID order (#433)
- The experimental `witsvid.Source` interface now requires a `GetWITSVID` method, so existing implementations need to add it (#410)
- Other dependency updates.

### Fixed

- The TLS configurations built by `spiffetls/tlsconfig` that verify the peer X509-SVID now also verify and authorize it on resumed sessions, which Go does not pass to `VerifyPeerCertificate`. Authorizers are now also called on resumed handshakes, and mTLS servers fall back to a full handshake when the client certificate of a session no longer verifies (#447)
- Bundle parsing no longer fails on JWKS entries with an unsupported key type, or in `spiffebundle` a missing or unknown `use`. Those entries are now ignored, as the SPIFFE bundle specification requires (#444, #448)
- The federation handler now sets the `Allow` header on 405 responses (#434)


## [2.9.0] - 2026-10-05

### Added

- `spiffeid.MatchIDPrefix` matcher and `tlsconfig.AuthorizeIDPrefix` authorizer, which accept any SPIFFE ID in the same trust domain whose path matches the given prefix's path or extends it on a segment boundary. The prefix must have a nonempty path, otherwise no ID matches (#406)

### Changed

- `PeerID` on connections returned by `spiffetls`, and `spiffetls.PeerIDFromConn`, now complete the TLS handshake if needed, so the peer ID can be retrieved before the first read. When the handshake is still pending, the call performs I/O like a `Read` would and honors the connection deadlines (#422)


## [2.8.2] - 2026-09-18

### Fixed

- Data race in `workloadapi.X509Source` and `workloadapi.JWTSource` when reading bundles while the Workload API watcher updates them (#420)


## [2.8.1] - 2026-06-19

### Changed

- WIT bundle JWKS entries now include `"use": "wit-svid"` as required by the SPIFFE WIT spec (#395)


## [2.8.0] - 2026-06-16

### Added

- Experimental SPIFFE Broker API protobuf definitions in the new `exp/proto/spiffe/broker` package (#388)


## [2.7.0] - 2026-06-03

### Added

- Experimental support for WIT-SVIDs, including the new `exp/svid/witsvid` and `exp/bundle/witbundle` packages and Workload API client support for fetching and watching WIT-SVIDs and WIT bundles (#385, #391)

### Changed

- X509-SVID verification now rejects leaf certificates with a SPIFFE ID that has a root path (#375)
- Other dependency updates.


## [2.6.0] - 2025-08-21

### Changed

- Minimum Go version is now go1.24.0, following our support policy.
- Other dependency updates.


## [2.5.0] - 2025-01-31

### Added

- workloadapi.TargetFromAddress function to parse out a gRPC target from a SPIFFE_ENDPOINT_SOCKET compatible address (#321)

### Changed

- Minimum Go version is now go1.22.11, matching our downstream dependencies (#325)

## [2.4.0] - 2024-10-05

### Added

- Support for using a custom backoff strategy in the Workload API client (#302)
- Support for a default JWT-SVID picker (#301)

## [2.3.0] - 2024-06-17

### Changed

- Empty bundles are now supported, in alignment with the SPIFFE specification (#288)

## [2.2.0] - 2024-04-01

### Changed

- Upgraded to go-jose v4 which has a stronger security posture than v3. Go-spiffe was not impacted by the security weaknesses of v3 due to stringing algorithm checking that is now handled by go-jose v4 (#276)

### Fixed

- Makefile invocation for Apple Silicon-based Macs (#275)

### Added

- Support Ed25519 keys for Workload SVIDs (#248)

## [2.1.7] - 2024-01-17

### Fixed

- Panic if the Workload API returned a malformed JWT-SVID (#233)
- Race that causes WaitForUpdate to return immediately after watcher is initialized even if there is no update (#260)

## [2.1.6] - 2023-06-06

### Added

- Name convenience method to the spiffeid.TrustDomain type (#228)

## [2.1.5] - 2023-05-26

### Added

- PeerIDFromConnectionState method for extracting the peer ID from TLS connection state (#225)

### Changed

- The `tlsconfig` to enforce a minimum TLS version of TLS1.2 (#226)

### Fixed

- Panic when failing to parse raw SVID response returned from the Workload API (#223)


## [2.1.4] - 2023-03-31

### Added

- Support for the SVID hints obtained from the Workload API (#220)

## [2.1.3] - 2023-03-16

### Changed

- JoinPathSegments properly disallows dot segments (#221)

### Added

- ValidatePathSegment function for validating an individual path segment (#221)

## [2.1.2] - 2023-01-09

### Changed
- Minimum supported go version to 1.17 (#209)

## [2.1.1] - 2022-06-29

### Added
- Support for dialing named pipes using an npipe URL scheme (#198)

## [2.1.0] - 2022-04-29

### Added
- The workloadapi.WatchX509Bundles method which watches X.509 bundles from the Workload API (#192)
- The workloadapi.WithNamedPipeName option to support connecting to the Workload API via named pipes (#190)
- The workloadapi.FetchJWTSVIDs method which fetches multiple JWT-SVIDs from the Workload API, instead of just the first (#187)
- The x509bundle.ParseRaw method for creating a bundle from raw ASN.1 encoded certificates (#192)

### Changed
- The spiffeid.ID String() method no longer causes an allocation (#185)
