package firewall

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/ulfox/nettrust/firewall/cache"
	"github.com/ulfox/nettrust/firewall/nftables"
)

// FirewallBackend interface for implementing different firewall backends. nftables, iptables, iptables-nft
type FirewallBackend interface {
	AddIPv4Rule(ip string) error
	DeleteIPv4Rule(ip string) error
	AddIPv4NetworkRule(cidr string) error
	DeleteIPv4NetworkRule(cidr string) error
	AddIPv4Set(n string) error
	AddIPv4SetRule(n string) error
	AddIPv4ToSetRule(n, ip string) error
	DeleteIPv4FromSetRule(n, ip string) error
	AddRejectVerdict() error
}

// Firewall for managing firewall rules
type Firewall struct {
	logger  *logrus.Logger
	fwl     *logrus.Entry
	ingress chan net.IP
	FirewallBackend
	table, chain, authorizedSet       string
	Cache                             *cache.Authorized
	blacklistHosts, blacklistNetworks []string
	ttlCheckTicker                    int
}

func (f *Firewall) backendExecutor(t string) (*FirewallBackend, error) {
	var beE FirewallBackend

	if t == "nftables" {
		nft, err := nftables.NewFirewallBackend(f.table, f.chain, f.logger)
		if err != nil {
			return nil, err
		}
		beE = nft

		return &beE, nil
	}

	if t == "iptables" || t == "iptables-legacy" || t == "iptables-nft" {
		return nil, fmt.Errorf("[%s] is not yet supported", t)
	}

	return nil, fmt.Errorf("not supported firewall backend [%s]", t)
}

// NewFirewall for creating a new firewall
func NewFirewall(t, table, chain string, logger *logrus.Logger) (*Firewall, error) {
	if table == "" {
		return nil, fmt.Errorf("table name not allowed to be empty")
	}

	if chain == "" {
		return nil, fmt.Errorf("chain name not allowed to be empty")
	}

	fw := &Firewall{
		logger:            logger,
		ingress:           make(chan net.IP),
		table:             table,
		chain:             chain,
		blacklistHosts:    []string{},
		blacklistNetworks: []string{},
	}

	beE, err := fw.backendExecutor(t)
	if err != nil {
		return nil, err
	}

	fw.FirewallBackend = *beE

	log := fw.logger.WithFields(logrus.Fields{
		"Component": "Firewall",
		"Stage":     "Authorizer",
	})
	fw.fwl = log

	return fw, nil
}

// SetBlacklists for adding blacklist hosts and networks
func (f *Firewall) SetBlacklists(blacklistHosts, blacklistNetworks []string) {
	f.blacklistHosts = blacklistHosts
	f.blacklistNetworks = blacklistNetworks
}

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

// TTLCacheChecker spawns a goroutine for checking cache for authorized hosts with expired ttl
func (f *Firewall) TTLCacheChecker(ttl, ttlCheckTicker int, authorizedSet string) (*ServiceContext, error) {
	if f.fwl == nil {
		return nil, fmt.Errorf(ErrNilFW)
	}

	f.ttlCheckTicker = ttlCheckTicker
	f.authorizedSet = authorizedSet

	if f.ttlCheckTicker < 1 {
		return nil, fmt.Errorf(ErrTTL)
	} else if f.ttlCheckTicker < 30 {
		f.logger.Warnf(WarnTTL)
	}

	if authorizedSet == "" {
		return nil, fmt.Errorf(ErrSetName)
	}

	f.Cache = cache.NewCache(ttl)

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

				for h := range f.Cache.Hosts {
					l.Infof("Removing host [%s] from firewall rules", h)
					err := f.DeleteIPv4FromSetRule(f.authorizedSet, h)
					if err != nil {
						l.Error(err)
					}
					f.Cache.Delete(h)
				}

				l.Info("Bye!")
				wg.Done()
				return
			case <-ticker.C:
				if f.Cache.TTL < 0 {
					break
				}
				l.Debug("Checking cache for expired hosts")
				for _, h := range f.Cache.Expired() {
					l.Debugf("Host [%s] has expired. Removing from firewall rules", h)
					err := f.DeleteIPv4FromSetRule(f.authorizedSet, h)
					if err != nil {
						l.Error(err)
					}
					l.Debugf("Deleting host [%s] from cache", h)
					f.Cache.Delete(h)
				}
			default:
				time.Sleep(time.Millisecond * 50)
			}
		}
	}(ctx, &serviceWG, f.fwl)

	return firewallCacheContext, nil
}
