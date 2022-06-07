//go:build !windows
// +build !windows

package workloadapi

func validateAddressCasesOS() []validateAddressCase {
	return []validateAddressCase{
		{
			addr: "unix:opaque",
			err:  "workload endpoint unix socket URI must not be opaque",
		},
		{
			addr: "unix://",
			err:  "workload endpoint unix socket URI must include a path",
		},
		{
			addr: "unix://foo?whatever",
			err:  "workload endpoint unix socket URI must not include query values",
		},
		{
			addr: "unix://foo#whatever",
			err:  "workload endpoint unix socket URI must not include a fragment",
		},
		{
			addr: "unix://john:doe@foo/path",
			err:  "workload endpoint unix socket URI must not include user info",
		},
		{
			addr: "unix://foo",
			err:  "",
		},
	}
}
