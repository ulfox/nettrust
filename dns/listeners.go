package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
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

// dnsTTLCacheManager spawns a goroutine for checking cache for expired queries
func (s *Server) dnsTTLCacheManager() (*ServiceContext, error) {
	if s.cache == nil {
		return nil, fmt.Errorf(errNil)
	}

	s.logger.WithFields(logrus.Fields{
		"Component": "DNS Cache",
		"Stage":     "Init",
	}).Info("Starting DNS TTL Cache Manager")

	dnsCacheContext := &ServiceContext{}

	var serviceWG sync.WaitGroup
	dnsCacheContext.wg = &serviceWG

	ctx, cancel := context.WithCancel(context.Background())
	dnsCacheContext.cancel = cancel

	serviceWG.Add(1)
	go func(ctx context.Context, wg *sync.WaitGroup, l *logrus.Entry) {
		l = l.WithFields(logrus.Fields{
			"Component": "DNS Cache",
			"Stage":     "Cache Watcher",
		})
		ticker := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-ctx.Done():
				l = l.WithFields(logrus.Fields{
					"Component": "DNS Cache",
					"Stage":     "Term",
				})

				l.Info("Bye!")
				wg.Done()
				return
			case <-ticker.C:
				if s.cache.GetTTL() < 0 {
					break
				}
				l.Debug("Checking DNS Cache")
				for _, h := range s.cache.ExpiredQueries() {
					l.Debugf("Deleting host [%s] from cache", h)
					s.cache.Delete(h)
				}
				for _, h := range s.cache.ExpiredMXQueries() {
					l.Debugf("Deleting host [%s] from NX cache", h)
					s.cache.DeleteNX(h)
				}
			default:
				time.Sleep(time.Millisecond * 50)
			}
		}
	}(ctx, &serviceWG, s.fwdl)

	return dnsCacheContext, nil
}

// UDPListenBackground for spawning a udp DNS Server
func (s *Server) UDPListenBackground(fn func(resp *dns.Msg) error) *ServiceContext {
	s.logger.WithFields(logrus.Fields{
		"Component": "DNS Server",
		"Stage":     "Init",
	}).Info("Starting UDP DNS Server")

	dnsServerContext := &ServiceContext{}

	var serviceListenerWG sync.WaitGroup
	dnsServerContext.wg = &serviceListenerWG

	ctxListener, cancelListener := context.WithCancel(context.Background())
	dnsServerContext.cancel = cancelListener

	s.udpServer = &dns.Server{
		Addr: s.listenAddr, Net: "udp",
		Handler: dns.HandlerFunc(
			func(w dns.ResponseWriter, r *dns.Msg) {
				s.fwd(w, r, fn)
			},
		),
	}

	serviceListenerWG.Add(1)
	go func(wg *sync.WaitGroup, srv *dns.Server) {
		l := s.logger.WithFields(logrus.Fields{
			"Component": "[UDP] DNSServer",
			"Stage":     "Init",
		})

		l.Info("Starting")
		if err := srv.ListenAndServe(); err != nil {
			l.Error(err)
		}
		wg.Done()
	}(&serviceListenerWG, s.udpServer)

	serviceListenerWG.Add(1)
	go func(ctx, ctxOnErr context.Context, wg *sync.WaitGroup, srv *dns.Server) {
		l := s.logger.WithFields(logrus.Fields{
			"Component": "[UDP] DNSServer",
			"Stage":     "Term",
		})

		for {
			select {
			case <-ctx.Done():
				if err := srv.Shutdown(); err != nil {
					l.Fatal(err)
				}
				s.cacheContext.Expire()
				s.cacheContext.Wait()
				l.Info("Bye!")
				wg.Done()
				return
			case <-ctxOnErr.Done():
				s.killOnErr()
			default:
				time.Sleep(time.Millisecond * 50)
			}
		}
	}(ctxListener, s.ctxOnErr, &serviceListenerWG, s.udpServer)

	return dnsServerContext
}

// TCPListenBackground for spawning a tcp DNS Server
func (s *Server) TCPListenBackground(fn func(resp *dns.Msg) error) *ServiceContext {
	s.logger.WithFields(logrus.Fields{
		"Component": "DNS Server",
		"Stage":     "Init",
	}).Info("Starting TCP DNS Server")

	dnsServerContext := &ServiceContext{}

	var serviceListenerWG sync.WaitGroup
	dnsServerContext.wg = &serviceListenerWG

	ctxListener, cancelListener := context.WithCancel(context.Background())
	dnsServerContext.cancel = cancelListener

	s.tcpServer = &dns.Server{
		Addr: s.listenAddr, Net: "tcp",
		Handler: dns.HandlerFunc(
			func(w dns.ResponseWriter, r *dns.Msg) {
				s.fwd(w, r, fn)
			},
		),
	}

	serviceListenerWG.Add(1)
	go func(wg *sync.WaitGroup, srv *dns.Server) {
		l := s.logger.WithFields(logrus.Fields{
			"Component": "[TCP] DNSServer",
			"Stage":     "Init",
		})

		if s.listenTLS {
			l = s.logger.WithFields(logrus.Fields{
				"Component": "[TLS] DNSServer",
				"Stage":     "Init",
			})

			srv.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{*s.listenCerts},
			}

			srv.Net = "tcp-tls"
		}

		l.Info("Starging")

		if err := srv.ListenAndServe(); err != nil {
			l.Error(err)
		}
		wg.Done()
	}(&serviceListenerWG, s.tcpServer)

	serviceListenerWG.Add(1)
	go func(ctx, ctxOnErr context.Context, wg *sync.WaitGroup, srv *dns.Server) {
		l := s.logger.WithFields(logrus.Fields{
			"Component": "[TCP] DNSServer",
			"Stage":     "Term",
		})
		for {
			select {
			case <-ctx.Done():
				if err := srv.Shutdown(); err != nil {
					l.Fatal(err)
				}
				s.cacheContext.Expire()
				s.cacheContext.Wait()
				l.Info("Bye!")
				wg.Done()
				return
			case <-ctxOnErr.Done():
				s.killOnErr()
			default:
				time.Sleep(time.Millisecond * 50)
			}
		}
	}(ctxListener, s.ctxOnErr, &serviceListenerWG, s.tcpServer)

	return dnsServerContext
}
