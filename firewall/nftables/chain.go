package nftables

import (
	"fmt"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
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

func (f *FirewallBackend) createChainInputWithEstablished(table *nftables.Table, chain *nftables.Chain) error {

	f.Lock()
	rules, err := f.nft.GetRule(table, chain)
	f.Unlock()

	if err != nil {
		return err
	}

	for _, rule := range rules {
		for _, e := range rule.Exprs {
			ct, ok := e.(*expr.Ct)
			if !ok {
				continue
			}
			if ct.Key == expr.CtKeySTATE {
				return nil
			}
		}
	}

	f.Lock()
	defer f.Unlock()

	f.nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ ct load state => reg 1 ]
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			// [ bitwise reg 1 = (reg=1 & 0x00000006 ) ^ 0x00000000 ]
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x06, 0x00, 0x00, 0x00},
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			// [ cmp neq reg 1 0x00000000 ]
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	err = f.nft.Flush()
	if err != nil {
		return err
	}

	f.nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load iifname => reg 1 ]
			&expr.Meta{
				Register: 1,
				Key:      expr.MetaKeyIIFNAME,
			},
			// [ cmp eq reg 1 0x00006f6c 0x00000000 0x00000000 0x00000000 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x6c, 0x6f, 0x00, 0x00},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	return f.nft.Flush()
}

// AddRejectVerdict is responsible for appending a reject verdict at the end of the chain. If reject verdict
// is not a tailing verdict it will move it at the end by first creating a new reject verdict at the end of
// the chain and then deleting the existing one
func (f *FirewallBackend) AddRejectVerdict() error {
	f.Lock()
	rules, err := f.nft.GetRule(f.table, f.chain)
	f.Unlock()

	if err != nil {
		return err
	}

	totalRules := len(rules)
	for i, r := range rules {
		if len(r.Exprs) == 1 {
			_, ok := r.Exprs[0].(*expr.Counter)
			if !ok {
				continue
			}

			if i != (totalRules - 1) {
				f.logger.Info("reject is not a tailing rule. Re-creating as tailing")
				f.Lock()
				f.nft.AddRule(&nftables.Rule{
					Table: f.table,
					Chain: f.chain,
					Exprs: []expr.Any{
						&expr.Counter{},
						&expr.Reject{},
					},
				})
				err = f.nft.Flush()
				f.Unlock()

				if err != nil {
					return err
				}

				f.Lock()
				f.nft.DelRule(&nftables.Rule{
					Table:  f.table,
					Chain:  f.chain,
					Handle: r.Handle,
				})

				err = f.nft.Flush()
				f.Unlock()

				if err != nil {
					return err
				}
			}

			return nil
		}
	}

	f.Lock()
	defer f.Unlock()

	f.nft.AddRule(&nftables.Rule{
		Table: f.table,
		Chain: f.chain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Reject{},
		},
	})
	return f.nft.Flush()
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
