package firewall

var (
	ErrNilFW   string = "firewall has not been initialized, starting ttl cache checker is forbidden"
	ErrTTL     string = "ttl ticker can not be 0 or negative"
	ErrSetName string = "authorized set can not be empty"
	WarnTTL    string = "ttl ticker is set to be %d sec. Please note that cache checks are blocking, frequent calls means frequent blocks"
)
