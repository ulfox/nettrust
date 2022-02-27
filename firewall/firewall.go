package firewall

import (
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/ulfox/nettrust/firewall/nftables"
)

// backend interface for implementing different firewall backends. nftables, iptables, iptables-nft
type backend interface {
	AddIPv4Rule(ip string) error
	DeleteIPv4Rule(ip string) error
	AddIPv4NetworkRule(cidr string) error
	DeleteIPv4NetworkRule(cidr string) error
	AddIPv4Set(n string) error
	AddIPv4SetRule(n string) error
	AddIPv4ToSetRule(n, ip string) error
	DeleteIPv4FromAuthorizedList(n, ip string) error
	AddTailingReject() error
	FlushTable(t string) error
	DeleteChain(c string) error
	DeleteTable(t string) error
	GetIPv4AuthorizedHosts(s string) ([]net.IP, error)
	CreateIPv4Table(t string) error
	CreateIPv4Chain(t, c, ct string, ht int) error
	DropIPv4Input(t, c string) error
}

// Firewall for managing firewall rules
type Firewall struct {
	logger  *logrus.Logger
	ingress chan net.IP
	backend
	table, chain string
}

func (f *Firewall) backendExecutor(b, h string) (*backend, error) {
	var beE backend

	if h != "OUTPUT" && h != "FORWARD" {
		return nil, fmt.Errorf(errFWDHook, h)
	}

	if b == "nftables" {
		nft, err := nftables.NewFirewallBackend(h, f.table, f.chain)
		if err != nil {
			return nil, err
		}
		beE = nft

		return &beE, nil
	}

	if b == "iptables" || b == "iptables-nft" {
		return nil, fmt.Errorf(errNotSupportedFWDBackend, b)
	}

	return nil, fmt.Errorf(errUnknownFWDBackend, b)
}

// NewFirewall for creating a new firewall.
// Params: backend = nftables/iptables/iptables-nft.
//         hook    = OUTPUT/FORWARD.
//         table   = table name that will be used/created (nftables).
//         chain   = chain name that will be created.
func NewFirewall(
	backend, hook, table, chain string,
	dropInput bool,
	logger *logrus.Logger,
) (*Firewall, error) {

	if table == "" {
		return nil, fmt.Errorf(errEmptyName, "table")
	}

	if chain == "" {
		return nil, fmt.Errorf(errEmptyName, "chain")
	}

	fw := &Firewall{
		logger:  logger,
		ingress: make(chan net.IP),
		table:   table,
		chain:   chain,
	}

	log := fw.logger.WithFields(logrus.Fields{
		"Component": "Firewall",
		"Stage":     "Configure",
	})

	log.Infof(infoFWDCreate, hook)
	beE, err := fw.backendExecutor(backend, strings.ToUpper(hook))
	if err != nil {
		return nil, err
	}

	fw.backend = *beE

	if dropInput {
		log.Info(infoFWDInput)
		err = fw.DropIPv4Input(table, chain)
		if err != nil {
			return nil, err
		}
	}

	return fw, nil
}
