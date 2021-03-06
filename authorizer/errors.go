package authorizer

var (
	errNil                string = "authorizer has not been initialized, starting ttl cache checker is forbidden"
	errTTL                string = "ttl ticker can not be 0 or negative"
	errSetName            string = "authorized set can not be empty"
	errInvalidReply       string = "[Invalid] query has Qtype %s but we could not read answer for question: %s"
	errRcode              string = "[QuerryError] query [%s] returned rcode different than success or nxdomain. Rcode [%d]"
	warnTTL               string = "ttl ticker is set to be %d sec. Please note that cache checks are blocking, frequent calls means frequent blocks"
	warnPTRIPv6           string = "[PTR IPv6] Question %s resolved to %s but was not authorized. NetTrust does not support IPv6 yet"
	warnIPv6Support       string = "[IPv6] Question: %s Host: %s NetTrust does not support IPv6 yet"
	warnNotSupportedQuery string = "[Not Supported] Question type [%d] for question %s"
	infoPTRIPv4           string = "[PTR IPv4] Question %s with host %s resolved to %s"
	infoAuthBlacklist     string = "[Blacklisted] Question %s Host: %s"
	infoAuthBlock         string = "[No Answer] Question %s"
	infoAuthIPv6Block     string = "[No Answer] IPv6 Question %s"
	infoAuthExists        string = "[Already Authorized] Question %s Host: %s"
	infoAuth              string = "[Authorized] Question %s Hosts: [%s]"
	infoNXDomain          string = "[Name Error] Question %s returned NX Domain"
)
