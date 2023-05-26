# Changelog

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
