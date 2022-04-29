# Changelog

## [2.1.0] - 2022-04-29

### Added
- Added the workloadapi.WatchX509Bundles method which watches X.509 bundles from the Workload API (#192)
- Added the workloadapi.WithNamedPipeName option to support connecting to the Workload API via named pipes (#190)
- Added the workloadapi.FetchJWTSVIDs method which fetchs multiple JWT-SVIDs from the Workload API, instead of just the first (#187)
- Added the x509bundle.ParseRaw method for creating a bundle from raw ASN.1 encoded certificates (#192)

### Changed
- The spiffeid.ID String() method no longer causes an allocation (#185)
