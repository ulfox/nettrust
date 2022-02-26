package authorizer

import (
	"fmt"
	"log"

	"github.com/sirupsen/logrus"
	"github.com/ti-mo/conntrack"
	"github.com/ulfox/nettrust/authorizer/cache"
	"github.com/ulfox/nettrust/firewall"
)

// Authorizer for managing firewall rules
type Authorizer struct {
	logger                            *logrus.Logger
	fw                                *firewall.Firewall
	fwl                               *logrus.Entry
	cache                             *cache.Authorized
	conntrack                         *conntrack.Conn
	blacklistHosts, blacklistNetworks []string
	ttl, ttlCheckTicker               int
	authorizedSet                     string
	doNotFlushAuthorizedHosts         bool
}

// NewAuthorizer for creating a new Authorizer
func NewAuthorizer(
	ttl,
	ttlCheckTicker int,
	authorizedSet string,
	blacklistHosts, blacklistNetworks []string,
	doNotFlushAuthorizedHosts bool,
	fw *firewall.Firewall,
	logger *logrus.Logger) (*Authorizer, *ServiceContext, error) {

	c, err := conntrack.Dial(nil)
	if err != nil {
		return nil, nil, err
	}

	authorizer := &Authorizer{
		logger: logger,
		fwl: logger.WithFields(logrus.Fields{
			"Component": "Firewall",
			"Stage":     "Authorizer",
		}),
		blacklistHosts:            blacklistHosts,
		blacklistNetworks:         blacklistNetworks,
		ttl:                       ttl,
		ttlCheckTicker:            ttlCheckTicker,
		authorizedSet:             authorizedSet,
		fw:                        fw,
		cache:                     cache.NewCache(ttl),
		conntrack:                 c,
		doNotFlushAuthorizedHosts: doNotFlushAuthorizedHosts,
	}

	if authorizer.ttlCheckTicker < 1 {
		return nil, nil, fmt.Errorf(errTTL)
	} else if authorizer.ttlCheckTicker < 30 {
		authorizer.fwl.Warnf(warnTTL, authorizer.ttlCheckTicker)
	}

	if authorizer.authorizedSet == "" {
		return nil, nil, fmt.Errorf(errSetName)
	}

	cacheContext, err := authorizer.ttlCacheChecker()
	if err != nil {
		return nil, nil, err
	}

	hosts, err := authorizer.fw.GetIPv4AuthorizedHosts(authorizedSet)
	if err != nil {
		log.Fatal(err)
	}
	if len(hosts) > 0 {
		for _, h := range hosts {
			authorizer.fwl.Debugf(
				"Found host %s in %s set. Importing into cache",
				h,
				authorizedSet,
			)
			authorizer.cache.Register(h.String())
		}
	}

	return authorizer, cacheContext, nil
}
