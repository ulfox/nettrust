package nftables

import (
	"sync"

	"github.com/google/nftables"
	"github.com/sirupsen/logrus"
)

// FirewallBackend for nftables
type FirewallBackend struct {
	sync.Mutex
	logger               *logrus.Logger
	nft                  *nftables.Conn
	tableName, chainName string
	table                *nftables.Table
	chain                *nftables.Chain
}

// NewFirewallBackend for creating a new nftables FirewaBackend
func NewFirewallBackend(t, c string, l *logrus.Logger) (*FirewallBackend, error) {
	firewallBackend := &FirewallBackend{
		logger:    l,
		nft:       &nftables.Conn{},
		tableName: t,
		chainName: c,
	}

	err := firewallBackend.CreateIPv4Table(t)
	if err != nil {
		return nil, err
	}

	nt, err := firewallBackend.getTable(t)
	if err != nil {
		return nil, err
	}

	err = firewallBackend.CreateIPv4Chain(
		t,
		c,
		string(nftables.ChainTypeFilter),
		int(nftables.ChainHookOutput),
	)
	if err != nil {
		return nil, err
	}

	nc, err := firewallBackend.getChain(c)
	if err != nil {
		return nil, err
	}

	firewallBackend.table = nt
	firewallBackend.chain = nc

	err = firewallBackend.CreateIPv4Table(t)
	if err != nil {
		return nil, err
	}

	nti, err := firewallBackend.getTable(t)
	if err != nil {
		return nil, err
	}

	err = firewallBackend.CreateIPv4Chain(
		t,
		"input",
		string(nftables.ChainTypeFilter),
		int(nftables.ChainHookInput),
	)
	if err != nil {
		return nil, err
	}

	nci, err := firewallBackend.getChain("input")
	if err != nil {
		return nil, err
	}

	err = firewallBackend.createChainInputWithEstablished(nti, nci)
	if err != nil {
		return nil, err
	}

	return firewallBackend, nil
}
