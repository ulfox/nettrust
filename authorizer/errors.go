package authorizer

var (
	errNil     string = "authorizer has not been initialized, starting ttl cache checker is forbidden"
	errTTL     string = "ttl ticker can not be 0 or negative"
	errSetName string = "authorized set can not be empty"
	warnTTL    string = "ttl ticker is set to be %d sec. Please note that cache checks are blocking, frequent calls means frequent blocks"
)
