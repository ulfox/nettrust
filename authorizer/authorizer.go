package authorizer

import (
	"fmt"

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
}

func NewAuthorizer(ttl, ttlCheckTicker int, authorizedSet string, blacklistHosts, blacklistNetworks []string, fw *firewall.Firewall, logger *logrus.Logger) (*Authorizer, *ServiceContext, error) {
	authorizer := &Authorizer{
		logger: logger,
		fwl: logger.WithFields(logrus.Fields{
			"Component": "Firewall",
			"Stage":     "Authorizer",
		}),
		blacklistHosts:    blacklistHosts,
		blacklistNetworks: blacklistNetworks,
		ttl:               ttl,
		ttlCheckTicker:    ttlCheckTicker,
		authorizedSet:     authorizedSet,
		fw:                fw,
		cache:             cache.NewCache(ttl),
		activeHosts:       &map[string]bool{},
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

	return authorizer, cacheContext, nil
}
