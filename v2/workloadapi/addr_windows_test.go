//go:build windows
// +build windows

package workloadapi

func validateAddressCasesOS() []validateAddressCase {
	return []validateAddressCase{
		{
			addr: "npipe:opaque",
			err:  "workload endpoint named pipe URI must not be opaque",
		},
		{
			addr: "npipe://",
			err:  "workload endpoint named pipe URI must include a path",
		},
		{
			addr: "npipe:////./pipe/foo?whatever",
			err:  "workload endpoint named pipe URI must not include query values",
		},
		{
			addr: "npipe:////./pipe/foo#whatever",
			err:  "workload endpoint named pipe URI must not include a fragment",
		},
		{
			addr: "npipe://john:doe@//./pipe/path",
			err:  "workload endpoint named pipe URI must not include user info",
		},
		{
			addr: "npipe:////computer/pipe/path",
			err:  "workload endpoint named pipe URI has an invalid path",
		},
		{
			addr: "npipe://host/pipe/path",
			err:  "workload endpoint named pipe URI must not include a host",
		},
		{
			addr: "npipe:////./pipe/path",
			err:  "",
		},
	}
}
