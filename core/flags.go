package core

import "flag"

var (
	doNotFlushTable                       *bool
	doNotFlushAuthorizedHosts, fwdTLS     *bool
	fwdAddr, fwdProto, fwdTLSCert         *string
	listenAddr, listenCert, listenCertKey *string
	listenTLS                             *bool

	firewallType                        *string
	whitelistLoopback, whitelistPrivate *bool

	authorizedTTL, ttlCheckTicker *int

	fileCFG *string

	dnsTTLCache *int
)

func init() {
	doNotFlushTable = flag.Bool(
		"do-not-flush-table",
		false,
		"Do not clean up tables when NetTrust exists. Use this flag if you want to continue to deny communication when NetTrust has exited",
	)
	doNotFlushAuthorizedHosts = flag.Bool(
		"do-not-flush-authorized-hosts",
		false,
		"Do not clean up the authorized hosts list on exit. Use this together with do-not-flush-table to keep the NetTrust table as is on exit",
	)
	fwdAddr = flag.String("fwd-addr", "", "NetTrust forward dns address")
	fwdProto = flag.String("fwd-proto", "", "NetTrust dns forward protocol")
	fwdTLS = flag.Bool(
		"fwd-tls",
		false,
		"Enable DoT. This expects that forward dns address supports DoT and fwd-proto is tcp",
	)
	fwdTLSCert = flag.String(
		"fwd-tls-cert",
		"",
		"path to certificate that will be used to validate forward dns hostname. If you do not set this, the the host root CAs will be used",
	)
	listenAddr = flag.String("listen-addr", "", "NetTrust listen dns address")
	listenTLS = flag.Bool("listen-tls", false, "Enable tls listener, tls listener works only with the TCP DNS Service, UDP will continue to serve in plaintext mode")
	listenCert = flag.String("listen-cert", "", "path to certificate that will be used by the TCP DNS Service to serve DoT")
	listenCertKey = flag.String("listen-cert-key", "", "path to the private key that will be used by the TCP DNS Service to serve DoT")
	firewallType = flag.String("firewall-type", "", "NetTrust firewall type (nftables is only supported for now)")
	whitelistLoopback = flag.Bool(
		"whitelist-loopback",
		true,
		"Loopback network space 127.0.0.0/8 will be whitelisted (default true)",
	)
	whitelistPrivate = flag.Bool(
		"whitelist-private",
		true,
		"If 10.0.0.0/8, 172.16.0.0/16, 192.168.0.0/16, 100.64.0.0/10 will be whitelisted (default true)",
	)
	authorizedTTL = flag.Int(
		"authorized-ttl",
		0,
		"Number of seconds a authorized host will be active before NetTrust expires it and expect a DNS query again (-1 do not expire)",
	)
	ttlCheckTicker = flag.Int(
		"ttl-check-ticker",
		0,
		"How often NetTrust should check the cache for expired authorized hosts (Checking is blocking, do not put small numbers)",
	)
	fileCFG = flag.String("config", "", "Path to config.json")
	dnsTTLCache = flag.Int("dns-ttl-cache", 0, "Number of seconds dns queries stay in cache (-1 to disable caching)")
}
