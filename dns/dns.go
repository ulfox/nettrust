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

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	qc "github.com/ulfox/nettrust/dns/cache"
)

// Server defines NetTrust DNS Server proxy. The server invokes firewall calls also
type Server struct {
	sync.Mutex

	listenAddr, fwdAddr, fwdProto string
	listenTLS, fwdTLS, sigOnce    bool
	dnsTTLCache                   int
	listenCerts                   *tls.Certificate
	logger                        *logrus.Logger
	fwdl                          *logrus.Entry
	client                        *dns.Client
	udpServer, tcpServer          *dns.Server
	cancelOnErr                   context.CancelFunc
	ctxOnErr                      context.Context
	cache                         *qc.Queries
	cacheContext                  *ServiceContext
}

// NewDNSServer for creating a new NetTrust DNS Server proxy
func NewDNSServer(
	laddr, faddr, fwdProto, listenCert, ListenCertKey, clientCaCert string,
	listenTLS, fwdTLS bool,
	dnsTTLCache int,
	logger *logrus.Logger,
) (*Server, error) {

	if laddr == "" || faddr == "" {
		return nil, fmt.Errorf(errFWDNSAddr)
	}

	if fwdTLS && fwdProto != "tcp" {
		return nil, fmt.Errorf(errFWDTLS)
	}

	if fwdProto != "udp" && fwdProto != "tcp" {
		return nil, fmt.Errorf(errFWDNSProto)
	}

	host, port, err := net.SplitHostPort(faddr)
	if err != nil {
		return nil, err
	}

	if host == "" || port == "" {
		return nil, fmt.Errorf(errFWDNSAddrInvalid, host, port)
	}

	if fwdTLS && port == "53" {
		logger.Warn(warnFWDTLSPort)
	}

	client := &dns.Client{Net: fwdProto}
	if fwdTLS {
		client.Net = "tcp-tls"
	}

	if fwdTLS && clientCaCert != "" {
		certPool, err := loadClientCaCert(clientCaCert)
		if err != nil {
			return nil, err
		}
		client.TLSConfig = &tls.Config{
			RootCAs: certPool,
		}
	}

	server := &Server{
		listenAddr:  laddr,
		listenTLS:   listenTLS,
		fwdAddr:     faddr,
		fwdProto:    fwdProto,
		fwdTLS:      fwdTLS,
		dnsTTLCache: dnsTTLCache,
		logger:      logger,
		client:      client,
		cache:       qc.NewCache(dnsTTLCache),
	}

	if listenTLS {
		cert, err := tls.LoadX509KeyPair(listenCert, ListenCertKey)
		if err != nil {
			return nil, err
		}
		server.listenCerts = &cert
	}

	server.fwdl = server.logger.WithFields(logrus.Fields{
		"Component": "DNS Server",
		"Stage":     "Forward",
	})

	server.ctxOnErr, server.cancelOnErr = context.WithCancel(context.Background())

	server.cacheContext, err = server.dnsTTLCacheManager()
	if err != nil {
		return nil, err
	}

	return server, nil
}

func loadClientCaCert(ca string) (*x509.CertPool, error) {
	f, err := os.Stat(ca)
	if os.IsNotExist(err) {
		return nil, err
	}

	if f.IsDir() {
		return nil, fmt.Errorf(errNotAFile, ca)
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
