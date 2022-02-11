package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/ulfox/nettrust/dns/cache"
	"github.com/ulfox/nettrust/firewall"
)

// Server defines NetTrust DNS Server proxy. The server invokes firewall calls also
type Server struct {
	sync.Mutex

	listenAddr, fwdAddr, authorizedSet, fwdProto string
	logger                                       *logrus.Logger
	fwl                                          *logrus.Entry
	udpServer, tcpServer                         *dns.Server
	fw                                           *firewall.Firewall
	Cache                                        *cache.Authorized
	blacklistHosts, blacklistNetworks            []string
}

// NewDNSServer for creating a new NetTrust DNS Server proxy
func NewDNSServer(laddr, faddr, fwdProto string, ttl int, logger *logrus.Logger) (*Server, error) {
	if laddr == "" || faddr == "" {
		return nil, fmt.Errorf("forward dns host: addr  can not be empty")
	}
	if fwdProto != "udp" && fwdProto != "tcp" {
		return nil, fmt.Errorf("forward tcp proto can be either tcp or udp")
	}

	server := &Server{
		listenAddr: laddr,
		fwdAddr:    faddr,
		fwdProto:   fwdProto,
		logger:     logger,
		Cache:      cache.NewCache(ttl),
	}

	return server, nil
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

// FirewallStart creates a new firewall and starts a goroutine for checking expired hosts in the cache. Expired hosts are checked each 30 sec, does nothing if TTL < 0
func (s *Server) FirewallStart(t, table, chain, authorizedSet string, blacklistHosts, blacklistNetworks []string) (*firewall.Firewall, *ServiceContext, error) {
	s.blacklistHosts = blacklistHosts
	s.blacklistNetworks = blacklistNetworks
	s.authorizedSet = authorizedSet

	fw, err := firewall.NewFirewall(t, table, chain, s.logger)
	if err != nil {
		return nil, nil, err
	}

	s.fw = fw

	log := s.logger.WithFields(logrus.Fields{
		"Component": "Firewall",
		"Stage":     "Authorizer",
	})
	s.fwl = log

	firewallContext := &ServiceContext{}

	var serviceWG sync.WaitGroup
	firewallContext.wg = &serviceWG

	ctx, cancel := context.WithCancel(context.Background())
	firewallContext.cancel = cancel

	serviceWG.Add(1)
	go func(ctx context.Context, wg *sync.WaitGroup, c *cache.Authorized, l *logrus.Entry) {
		ticker := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-ctx.Done():
				l := l.WithFields(logrus.Fields{
					"Component": "Firewall",
					"Stage":     "Deauthorize",
				})

				for h := range c.Hosts {
					l.Infof("Removing host [%s] from firewall rules", h)
					err := fw.DeleteIPv4FromSetRule(s.authorizedSet, h)
					if err != nil {
						l.Error(err)
					}
					c.Delete(h)
				}

				l.Info("Bye!")
				wg.Done()
				return
			case <-ticker.C:
				l.Debug("Checking cache for expired hosts")
				for _, h := range s.Cache.Expired() {
					l.Debugf("Host [%s] has expired. Removing from firewall rules", h)
					err := fw.DeleteIPv4FromSetRule(s.authorizedSet, h)
					if err != nil {
						l.Error(err)
					}
					l.Debugf("Deleting host [%s] from cache", h)
					c.Delete(h)
				}
			default:
				time.Sleep(time.Millisecond * 50)
			}
		}
	}(ctx, &serviceWG, s.Cache, log)

	return fw, firewallContext, nil
}

// UDPListenBackground for spawning a udp DNS Server
func (s *Server) UDPListenBackground() *ServiceContext {
	log := s.logger.WithFields(logrus.Fields{
		"Component": "DNS Server",
		"Stage":     "Init",
	})

	log.Info("Starting UDP DNS Server")

	dnsServerContext := &ServiceContext{}

	var serviceListenerWG sync.WaitGroup
	dnsServerContext.wg = &serviceListenerWG

	ctxListener, cancelListener := context.WithCancel(context.Background())
	dnsServerContext.cancel = cancelListener

	s.udpServer = &dns.Server{
		Addr: s.listenAddr, Net: "udp",
		Handler: dns.HandlerFunc(
			func(w dns.ResponseWriter, r *dns.Msg) {
				s.fwd(w, r)
			},
		),
	}

	serviceListenerWG.Add(1)
	go func(wg *sync.WaitGroup, srv *dns.Server, l *logrus.Entry) {
		l = l.WithFields(logrus.Fields{
			"Component": "[UDP] DNSServer",
			"Stage":     "Init",
		})

		l.Info("Starting")
		if err := srv.ListenAndServe(); err != nil {
			l.Error(err)
		}
		wg.Done()
	}(&serviceListenerWG, s.udpServer, log)

	serviceListenerWG.Add(1)
	go func(ctx context.Context, wg *sync.WaitGroup, srv *dns.Server, l *logrus.Entry) {
		for {
			select {
			case <-ctx.Done():
				l = l.WithFields(logrus.Fields{
					"Component": "[UDP] DNSServer",
					"Stage":     "Term",
				})

				if err := srv.Shutdown(); err != nil {
					l.Fatal(err)
				}
				l.Info("Bye!")
				wg.Done()
				return
			default:
				time.Sleep(time.Millisecond * 50)
			}
		}
	}(ctxListener, &serviceListenerWG, s.udpServer, log)

	return dnsServerContext
}

// TCPListenBackground for spawning a tcp DNS Server
func (s *Server) TCPListenBackground() *ServiceContext {
	log := s.logger.WithFields(logrus.Fields{
		"Component": "DNS Server",
		"Stage":     "Init",
	})

	log.Info("Starting TCP DNS Server")

	dnsServerContext := &ServiceContext{}

	var serviceListenerWG sync.WaitGroup
	dnsServerContext.wg = &serviceListenerWG

	ctxListener, cancelListener := context.WithCancel(context.Background())
	dnsServerContext.cancel = cancelListener

	s.tcpServer = &dns.Server{
		Addr: s.listenAddr, Net: "tcp",
		Handler: dns.HandlerFunc(
			func(w dns.ResponseWriter, r *dns.Msg) {
				s.fwd(w, r)
			},
		),
	}

	serviceListenerWG.Add(1)
	go func(wg *sync.WaitGroup, srv *dns.Server, l *logrus.Entry) {
		l = l.WithFields(logrus.Fields{
			"Component": "[TCP] DNSServer",
			"Stage":     "Init",
		})

		l.Info("Starging")
		if err := srv.ListenAndServe(); err != nil {
			l.Error(err)
		}
		wg.Done()
	}(&serviceListenerWG, s.tcpServer, log)

	serviceListenerWG.Add(1)
	go func(ctx context.Context, wg *sync.WaitGroup, srv *dns.Server, l *logrus.Entry) {
		for {
			select {
			case <-ctx.Done():
				l = l.WithFields(logrus.Fields{
					"Component": "[TCP] DNSServer",
					"Stage":     "Term",
				})

				if err := srv.Shutdown(); err != nil {
					l.Fatal(err)
				}
				l.Info("Bye!")
				wg.Done()
				return
			default:
				time.Sleep(time.Millisecond * 50)
			}
		}
	}(ctxListener, &serviceListenerWG, s.tcpServer, log)

	return dnsServerContext
}

func (s *Server) fwd(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	host, port, err := net.SplitHostPort(s.fwdAddr)
	if err != nil {
		s.logger.Error(err)
		dns.HandleFailed(w, req)
		return
	}
	if host == "" || port == "" {
		dns.HandleFailed(w, req)
		s.logger.Fatalf("forward dns address is not valid [%s:%s]", host, port)
		return
	}

	c := &dns.Client{Net: s.fwdProto}
	resp, _, err := c.Exchange(req, s.fwdAddr)
	if err != nil {
		s.logger.Error(err)
		dns.HandleFailed(w, req)
		return
	}

	err = s.handleRequest(resp)
	if err != nil {
		s.logger.Error(err)
		dns.HandleFailed(w, req)
		return
	}

	err = w.WriteMsg(resp)
	if err != nil {
		s.logger.Error(err)
		dns.HandleFailed(w, req)
	}
}
