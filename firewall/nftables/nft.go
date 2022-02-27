package nftables

import (
	"sync"

	"github.com/google/nftables"
)

// FirewallBackend for nftables
type FirewallBackend struct {
	sync.Mutex
	nft                  *nftables.Conn
	tableName, chainName string
	table                *nftables.Table
	chain                *nftables.Chain
}

// NewFirewallBackend for creating a new nftables FirewaBackend
func NewFirewallBackend(hook, table, chain string) (*FirewallBackend, error) {
	firewallBackend := &FirewallBackend{
		nft:       &nftables.Conn{},
		tableName: table,
		chainName: chain,
	}

	// HookType [OUTPUT/FORWARD]
	var hT nftables.ChainHook
	// ChainType [FILTER]. We may add more ChainTypes in the future
	// but for now NetFilter will handle only Host Outbound requests
	// on FILTER/OUTPUT or for intermediate gateways on FILTER/FORWARD
	var cT nftables.ChainType
	switch hook {
	case "OUTPUT":
		hT = nftables.ChainHookOutput
		cT = nftables.ChainTypeFilter
	case "FORWARD":
		hT = nftables.ChainHookForward
		cT = nftables.ChainTypeFilter
	default:
		hT = nftables.ChainHookOutput
		cT = nftables.ChainTypeFilter
	}

	err := firewallBackend.CreateIPv4Table(table)
	if err != nil {
		return nil, err
	}

	nt, err := firewallBackend.getTable(table)
	if err != nil {
		return nil, err
	}

	err = firewallBackend.CreateIPv4Chain(
		table,
		chain,
		string(cT),
		int(hT),
	)
	if err != nil {
		return nil, err
	}

	nc, err := firewallBackend.getChain(chain)
	if err != nil {
		return nil, err
	}

	firewallBackend.table = nt
	firewallBackend.chain = nc

	return firewallBackend, nil
}

// DropIPv4Input for creating FILTER/INPUT chain that drops all inbound traffic except
// loopback traffic or established,related traffic
func (f *FirewallBackend) DropIPv4Input(table, chain string) error {
	err := f.CreateIPv4Table(table)
	if err != nil {
		return err
	}

	nti, err := f.getTable(table)
	if err != nil {
		return err
	}

	err = f.CreateIPv4Chain(
		table,
		"input",
		string(nftables.ChainTypeFilter),
		int(nftables.ChainHookInput),
	)
	if err != nil {
		return err
	}

	nci, err := f.getChain("input")
	if err != nil {
		return err
	}

	err = f.createChainInputWithEstablished(nti, nci)
	if err != nil {
		return err
	}

	return nil
}
