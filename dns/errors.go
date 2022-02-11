package dns

var (
	ErrFWDNSAddr        string = "forward dns host: addr  can not be empty"
	ErrFWDNSAddrInvalid string = "forward dns address is not valid [%s:%s]"
	ErrFWDNSProto       string = "forward tcp proto can be either tcp or udp"
	ErrFWDTLS           string = "forward tls requires proto to be tcp"
	ErrQuery            string = "invalid query, no questions"
	ErrNotAFile         string = "[%s] is a directory"
	WarnFWDTLSPort      string = "forward tls is enabled but port is set to 53"
)
