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
		{
			addr: "tcp:opaque",
			err:  "workload endpoint tcp socket URI must not be opaque",
		},
		{
			addr: "tcp://",
			err:  "workload endpoint tcp socket URI must include a host",
		},
		{
			addr: "tcp://1.2.3.4:5?whatever",
			err:  "workload endpoint tcp socket URI must not include query values",
		},
		{
			addr: "tcp://1.2.3.4:5#whatever",
			err:  "workload endpoint tcp socket URI must not include a fragment",
		},
		{
			addr: "tcp://john:doe@1.2.3.4:5/path",
			err:  "workload endpoint tcp socket URI must not include user info",
		},
		{
			addr: "tcp://1.2.3.4:5/path",
			err:  "workload endpoint tcp socket URI must not include a path",
		},
		{
			addr: "tcp://foo",
			err:  "workload endpoint tcp socket URI host component must be an IP:port",
		},
		{
			addr: "tcp://1.2.3.4",
			err:  "workload endpoint tcp socket URI host component must include a port",
		},
		{
			addr: "tcp://1.2.3.4:5",
			err:  "",
		},
	}
}
