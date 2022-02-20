package dns

var (
	errFWDNSAddr           string = "forward dns host: addr  can not be empty"
	errFWDNSAddrInvalid    string = "forward dns address is not valid [%s:%s]"
	errFWDNSProto          string = "forward tcp proto can be either tcp or udp"
	errFWDTLS              string = "forward tls requires proto to be tcp"
	errQuery               string = "invalid query, no questions"
	errNotAFile            string = "[%s] is a directory"
	errManyQuestions       string = "[Invalid] query has more than 1 question [%s]"
	errCacheFetch          string = "[Cache] something went wrong, could not fetch dns object from cache for question: %s"
	errCacheRegister       string = "[Cache] could not register dns object with question %s to cache"
	errCacheCoulndNotRenew string = "[Cache] could not renew object for question %s"
	warnFWDTLSPort         string = "forward tls is enabled but port is set to 53"
	infoCacheObjExpired    string = "[Cache] dns cache object with question %s has expired, asking upstream"
	infoCacheObjFound      string = "[Cache] found dns object in cache for question %s"
)
