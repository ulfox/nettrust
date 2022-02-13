package authorizer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ServiceContext for canceling goroutins
type ServiceContext struct {
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

// Expire will call cancel to terminate a context immediately, causing the goroutine to exit
func (f *ServiceContext) Expire() {
	f.cancel()
}

// Wait ensures that the goroutine has exit successfully
func (f *ServiceContext) Wait() {
	f.wg.Wait()
}

// ttlCacheChecker spawns a goroutine for checking cache for authorized hosts with expired ttl
func (f *Authorizer) ttlCacheChecker() (*ServiceContext, error) {
	if f.fwl == nil {
		return nil, fmt.Errorf(ErrNil)
	}

	firewallCacheContext := &ServiceContext{}

	var serviceWG sync.WaitGroup
	firewallCacheContext.wg = &serviceWG

	ctx, cancel := context.WithCancel(context.Background())
	firewallCacheContext.cancel = cancel

	serviceWG.Add(1)
	go func(ctx context.Context, wg *sync.WaitGroup, l *logrus.Entry) {
		ticker := time.NewTicker(time.Duration(f.ttlCheckTicker) * time.Second)
		for {
			select {
			case <-ctx.Done():
				l := l.WithFields(logrus.Fields{
					"Component": "Firewall",
					"Stage":     "Deauthorize",
				})

				if !f.doNotFlushAuthorizedHosts {
					for h := range f.cache.Hosts {
						l.Infof("Removing host [%s] from firewall rules", h)
						err := f.fw.DeleteIPv4FromSetRule(f.authorizedSet, h)
						if err != nil {
							l.Error(err)
						}
						f.cache.Delete(h)
					}
				}

				l.Info("Bye!")
				wg.Done()
				return
			case <-ticker.C:
				if f.cache.TTL < 0 {
					break
				}
				l.Debug("Gathering active hosts from conntrack")
				activeHosts, err := f.conntrackDump()
				if err != nil {
					l.Error(err)
				}

				// Blocking call. If the expired hosts or cache is very big we may get dns bottleneck.
				// During f.cache.Expired() call, RequestHandler will not be able to serve dns requests
				l.Debug("Checking cache for expired hosts")
				for _, h := range f.cache.Expired() {
					_, ok := activeHosts[h]
					if ok {
						l.Debugf("Host [%s] has expired but is stil active. Renewing", h)
						f.cache.Renew(h)
						continue
					}

					// Blocking call, but we expect this to be fast to mitigate any wait that
					// RequestHandler may encounter
					l.Debugf("Host [%s] has expired. Removing from firewall rules", h)
					err := f.fw.DeleteIPv4FromSetRule(f.authorizedSet, h)
					if err != nil {
						l.Error(err)
					}

					// Blocking call, should be fast and not cause any delays to RequestHandler
					l.Debugf("Deleting host [%s] from cache", h)
					f.cache.Delete(h)
				}
			default:
				time.Sleep(time.Millisecond * 50)
			}
		}
	}(ctx, &serviceWG, f.fwl)

	return firewallCacheContext, nil
}
