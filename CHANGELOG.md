# Changelog

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
