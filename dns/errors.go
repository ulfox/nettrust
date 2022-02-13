package dns

var (
	errFWDNSAddr        string = "forward dns host: addr  can not be empty"
	errFWDNSAddrInvalid string = "forward dns address is not valid [%s:%s]"
	errFWDNSProto       string = "forward tcp proto can be either tcp or udp"
	errFWDTLS           string = "forward tls requires proto to be tcp"
	errQuery            string = "invalid query, no questions"
	errNotAFile         string = "[%s] is a directory"
	warnFWDTLSPort      string = "forward tls is enabled but port is set to 53"
)
