//go:build windows
// +build windows

package workloadapi

func validateAddressCasesOS() []validateAddressCase {
	return []validateAddressCase{
		{
			addr: "pipe:opaque",
			err:  "workload endpoint named pipe URI must not be opaque",
		},
		{
			addr: "pipe://",
			err:  "workload endpoint named pipe URI must include a path",
		},
		{
			addr: "pipe:////./pipe/foo?whatever",
			err:  "workload endpoint named pipe URI must not include query values",
		},
		{
			addr: "pipe:////./pipe/foo#whatever",
			err:  "workload endpoint named pipe URI must not include a fragment",
		},
		{
			addr: "pipe://john:doe@//./pipe/path",
			err:  "workload endpoint named pipe URI must not include user info",
		},
		{
			addr: "pipe:////computer/pipe/path",
			err:  "workload endpoint named pipe URI has an invalid path",
		},
		{
			addr: "pipe://host/pipe/path",
			err:  "workload endpoint named pipe URI must not include a host",
		},
		{
			addr: "pipe:////./pipe/path",
			err:  "",
		},
	}
}
