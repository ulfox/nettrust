package dns

var (
	ErrFWDNSAddr        string = "forward dns host: addr  can not be empty"
	ErrFWDNSAddrInvalid string = "forward dns address is not valid [%s:%s]"
	ErrFWDNSProto       string = "forward tcp proto can be either tcp or udp"
	ErrQuery            string = "invalid query, no questions"
)
