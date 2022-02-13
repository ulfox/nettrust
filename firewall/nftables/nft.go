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
func NewFirewallBackend(t, c string, logger *logrus.Logger) (*FirewallBackend, error) {
	firewallBackend := &FirewallBackend{
		logger:    logger,
		nft:       &nftables.Conn{},
		tableName: t,
		chainName: c,
	}

	nt, nc, err := firewallBackend.createIPv4Chain(t, c, string(nftables.ChainTypeFilter), int(nftables.ChainHookOutput))
	if err != nil {
		return nil, err
	}

	firewallBackend.table = nt
	firewallBackend.chain = nc

	nti, nci, err := firewallBackend.createIPv4Chain(t, "input", string(nftables.ChainTypeFilter), int(nftables.ChainHookInput))
	if err != nil {
		return nil, err
	}

	err = firewallBackend.createChainInputWithEstablished(nti, nci)
	if err != nil {
		return nil, err
	}

	return firewallBackend, nil
}
