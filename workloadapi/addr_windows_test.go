//go:build windows
// +build windows

package workloadapi

func validateAddressCasesOS() []validateAddressCase {
	return []validateAddressCase{
		{
			addr: "npipe:pipeName",
			err:  "",
		},
		{
			addr: "npipe:pipe/name",
			err:  "",
		},
		{
			addr: "npipe:pipe\\name",
			err:  "",
		},
		{
			addr: "npipe:",
			err:  "workload endpoint named pipe URI must include an opaque part",
		},
		{
			addr: "npipe://foo",
			err:  "workload endpoint named pipe URI must be opaque",
		},
		{
			addr: "npipe:pipeName?query",
			err:  "workload endpoint named pipe URI must not include query values",
		},
		{
			addr: "npipe:pipeName#fragment",
			err:  "workload endpoint named pipe URI must not include a fragment",
		},
	}
}
