package authorizer

var (
	errNil            string = "authorizer has not been initialized, starting ttl cache checker is forbidden"
	errTTL            string = "ttl ticker can not be 0 or negative"
	errSetName        string = "authorized set can not be empty"
	errInvalidReply   string = "[Invalid] query has Qtype %s but we could not read answer for question: %s"
	warnTTL           string = "ttl ticker is set to be %d sec. Please note that cache checks are blocking, frequent calls means frequent blocks"
	warnPTRIPv6       string = "[PTR IPv6] Question %s resolved to %s but was not authorized. NetTrust does not support IPv6 yet"
	warnIPv6Support   string = "[IPv6] Question: %s Host: %s NetTrust does not support IPv6 yet"
	infoNotHandled    string = "[Not Handled] Question %s - Is this local?"
	infoPTRIPv4       string = "[PTR IPv4] Question %s with host %s resolved to %s"
	infoAuthBlacklist string = "[Blacklisted] Question %s Host: %s"
	infoAuthBlock     string = "[Blocked] Question %s"
	infoAuthExists    string = "[Already Authorized] Question %s Host: %s"
	infoAuth          string = "[Authorized] Question %s Hosts: [%s]"
)
