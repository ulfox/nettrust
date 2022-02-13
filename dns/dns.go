package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Server defines NetTrust DNS Server proxy. The server invokes firewall calls also
type Server struct {
	sync.Mutex

	listenAddr, fwdAddr, fwdProto string
	fwdTLS, sigOnce               bool
	logger                        *logrus.Logger
	fwdl                          *logrus.Entry
	client                        *dns.Client
	udpServer, tcpServer          *dns.Server
	cancelOnErr                   context.CancelFunc
	ctxOnErr                      context.Context
}

// NewDNSServer for creating a new NetTrust DNS Server proxy
func NewDNSServer(laddr, faddr, fwdProto, cacert string, fwdTLS bool, logger *logrus.Logger) (*Server, error) {
	if laddr == "" || faddr == "" {
		return nil, fmt.Errorf(ErrFWDNSAddr)
	}

	if fwdTLS && fwdProto != "tcp" {
		return nil, fmt.Errorf(ErrFWDTLS)
	}

	if fwdProto != "udp" && fwdProto != "tcp" {
		return nil, fmt.Errorf(ErrFWDNSProto)
	}

	host, port, err := net.SplitHostPort(faddr)
	if err != nil {
		return nil, err
	}

	if host == "" || port == "" {
		return nil, fmt.Errorf(ErrFWDNSAddrInvalid, host, port)
	}

	if fwdTLS && port == "53" {
		logger.Warn(WarnFWDTLSPort)
	}

	client := &dns.Client{Net: fwdProto}
	if fwdTLS {
		client.Net = "tcp-tls"
	}

	if cacert != "" {
		certPool, err := loadCaCert(cacert)
		if err != nil {
			return nil, err
		}
		client.TLSConfig = &tls.Config{
			RootCAs: certPool,
		}
	}

	server := &Server{
		listenAddr: laddr,
		fwdAddr:    faddr,
		fwdProto:   fwdProto,
		fwdTLS:     fwdTLS,
		logger:     logger,
		client:     client,
	}

	server.fwdl = server.logger.WithFields(logrus.Fields{
		"Component": "DNS Server",
		"Stage":     "Forward",
	})

	server.ctxOnErr, server.cancelOnErr = context.WithCancel(context.Background())

	return server, nil
}

func loadCaCert(ca string) (*x509.CertPool, error) {
	f, err := os.Stat(ca)
	if os.IsNotExist(err) {
		return nil, err
	}

	if f.IsDir() {
		return nil, fmt.Errorf(ErrNotAFile, ca)
	}

	data, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(data)

	return certPool, nil
}

func (s *Server) killOnErr() {
	if s.sigOnce {
		return
	}

	s.Lock()
	s.sigOnce = true
	s.Unlock()

	s.fwdl.Error("nettrust is shutting down, sending SIGINT")
	err := syscall.Kill(syscall.Getegid(), syscall.SIGINT)
	if err != nil {
		s.fwdl.Error(err)
	}
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

func (s *Server) fwd(w dns.ResponseWriter, req *dns.Msg, fn func(resp *dns.Msg) error) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		s.qErr(w, req, fmt.Errorf(ErrQuery))
		return
	}

	resp, _, err := s.client.Exchange(req, s.fwdAddr)
	if err != nil {
		s.qErr(w, req, err)
		return
	}

	err = fn(resp)
	if err != nil {
		s.qErr(w, req, err)
		return
	}

	err = w.WriteMsg(resp)
	if err != nil {
		s.qErr(w, req, err)
	}
}

func (s *Server) qErr(w dns.ResponseWriter, req *dns.Msg, err error) {
	s.fwdl.Error(err)
	dns.HandleFailed(w, req)
}
