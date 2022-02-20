package core

var (
	errSameAddr             string = "listen address can not be the same as forward address"
	errListenTLSNoFile      string = "listen-tls is enabled but no %s was provided"
	errInvalidSocketAddress string = "address [%s] is not valid. Expected ip:port"
	errInvalidPort          string = "invalid port [%d] number"
	errNotValidIPv4Addr     string = "not a valid ipv4 address [%s]"
	errNotValidIPv4Network  string = "not a valid ipv4 network [%s]"

	// WarnOnExitFlushAuthorized will be printed when authorized hosts are preserved on NetTrust exit
	WarnOnExitFlushAuthorized string = "on exit NetTrust will not flush the authorized hosts list"

	// WarnOnExitFlush will be printed when on exit flush table is enabled
	WarnOnExitFlush string = "on exit flush table is enabled. Please set this to false if you wish to deny traffic to all if NetTrust is not running"
)
