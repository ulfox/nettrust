package nftables

var (
	errNoSuchCahin         string = "could not find chain [%s]"
	errNoSuchTable         string = "could not find table [%s]"
	errNotValidIPv4Addr    string = "[%s] does not appear to be a valid ipv4 ipaddr"
	errNotSuchIPv4NetRule  string = "could not find network rule with cidr [%s]"
	errNotSuchIPv4AddrRule string = "could not find rule with ip [%s]"
	errNoSuchIPv4SetRule   string = "could not find set rule with name [%s]"
)
