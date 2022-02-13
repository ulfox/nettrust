package authorizer

import (
	"fmt"
	"log"

	"github.com/sirupsen/logrus"
	"github.com/ulfox/nettrust/authorizer/cache"
	"github.com/ulfox/nettrust/firewall"
)

// Authorizer for managing firewall rules
type Authorizer struct {
	logger                            *logrus.Logger
	fw                                *firewall.Firewall
	fwl                               *logrus.Entry
	cache                             *cache.Authorized
	activeHosts                       *map[string]bool
	blacklistHosts, blacklistNetworks []string
	ttl, ttlCheckTicker               int
	authorizedSet                     string
	doNotFlushAuthorizedHosts         bool
}

func NewAuthorizer(
	ttl,
	ttlCheckTicker int,
	authorizedSet string,
	blacklistHosts, blacklistNetworks []string,
	doNotFlushAuthorizedHosts bool,
	fw *firewall.Firewall,
	logger *logrus.Logger) (*Authorizer, *ServiceContext, error) {

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
		activeHosts:               &map[string]bool{},
		doNotFlushAuthorizedHosts: doNotFlushAuthorizedHosts,
	}

	if authorizer.ttlCheckTicker < 1 {
		return nil, nil, fmt.Errorf(ErrTTL)
	} else if authorizer.ttlCheckTicker < 30 {
		authorizer.fwl.Warnf(WarnTTL, authorizer.ttlCheckTicker)
	}

	if authorizer.authorizedSet == "" {
		return nil, nil, fmt.Errorf(ErrSetName)
	}

	cacheContext, err := authorizer.ttlCacheChecker()
	if err != nil {
		return nil, nil, err
	}

	hosts, err := authorizer.fw.GetAuthorizedIPV4Hosts(authorizedSet)
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
