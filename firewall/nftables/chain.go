package nftables

import (
	"fmt"
	"strings"

	"github.com/google/nftables"
)

func (f *FirewallBackend) getChain(c string) (*nftables.Chain, error) {
	f.Lock()
	chains, err := f.nft.ListChains()
	f.Unlock()

	if err != nil {
		return nil, err
	}
	for _, t := range chains {
		if c == t.Name {
			return t, nil
		}
	}
	return nil, fmt.Errorf("could not find chain [%s]", c)
}

func (f *FirewallBackend) getTable(c string) (*nftables.Table, error) {
	f.Lock()
	tables, err := f.nft.ListTables()
	f.Unlock()

	if err != nil {
		return nil, err
	}

	for _, t := range tables {
		if c == t.Name {
			return t, nil
		}
	}

	return nil, fmt.Errorf("could not find table [%s]", c)
}

func (f *FirewallBackend) createIPv4Chain(table, chain, chainType string, hookType int) (*nftables.Table, *nftables.Chain, error) {
	nt, err := f.getTable(table)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "could not find table") {
			return nil, nil, err
		}
		f.Lock()
		nt = f.nft.AddTable(&nftables.Table{
			Name:   table,
			Family: nftables.TableFamilyIPv4,
		})
		f.Unlock()
	}

	// We should build cases on this in the future should we need to add
	// additional chain types
	var cT nftables.ChainType
	switch chainType {
	case string(nftables.ChainTypeFilter):
		cT = nftables.ChainTypeFilter
	}

	// same here, we should add additional hook ypes if we need
	var hT nftables.ChainHook
	switch hookType {
	case int(nftables.ChainHookOutput):
		hT = nftables.ChainHookOutput
	case int(nftables.ChainHookInput):
		hT = nftables.ChainHookInput
	}

	nc, err := f.getChain(chain)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "could not find chain") {
			return nil, nil, err
		}
		f.Lock()
		// drop by default.
		// If somehow the reject tailing rule is skipped,
		// this will introduced timeouts for processes
		// that request to access an non-authorized ip.
		outputPolicy := nftables.ChainPolicyDrop
		nc = f.nft.AddChain(&nftables.Chain{
			Name:     chain,
			Table:    nt,
			Type:     cT,
			Hooknum:  hT,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &outputPolicy,
		})
		f.Unlock()
	}

	f.Lock()
	defer f.Unlock()

	err = f.nft.Flush()
	if err != nil {
		return nil, nil, err
	}

	return nt, nc, nil
}

// Remove rules from chain. This will leave the chain with the defined policy
// If the policy is drop, we should run DeleteChain also if we want the host
// to be able to do network communication
func (f *FirewallBackend) FlushTable() error {
	f.Lock()
	defer f.Unlock()

	f.nft.FlushTable(f.table)

	return f.nft.Flush()
}

// Delete chain from the table. By removing the chain we allow all communication
// if no other rules are set by external tools
func (f *FirewallBackend) DeleteChain() error {
	f.Lock()
	defer f.Unlock()

	f.nft.DelChain(f.chain)

	return f.nft.Flush()
}
