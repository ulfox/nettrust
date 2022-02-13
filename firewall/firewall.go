package firewall

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
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
	FlushTable(t string) error
	DeleteChain(c string) error
	GetAuthorizedIPV4Hosts(s string) ([]net.IP, error)
}

// Firewall for managing firewall rules
type Firewall struct {
	logger  *logrus.Logger
	ingress chan net.IP
	FirewallBackend
	table, chain string
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
		logger:  logger,
		ingress: make(chan net.IP),
		table:   table,
		chain:   chain,
	}

	beE, err := fw.backendExecutor(t)
	if err != nil {
		return nil, err
	}

	fw.FirewallBackend = *beE

	return fw, nil
}
