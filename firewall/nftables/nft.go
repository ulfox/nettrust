package nftables

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
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

	nt, err := firewallBackend.getTable(t)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "could not find table") {
			return nil, err
		}
		firewallBackend.Lock()
		nt = firewallBackend.nft.AddTable(&nftables.Table{
			Name:   firewallBackend.tableName,
			Family: nftables.TableFamilyIPv4,
		})
		firewallBackend.Unlock()
	}
	firewallBackend.table = nt

	nc, err := firewallBackend.getChain(c)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "could not find chain") {
			return nil, err
		}
		firewallBackend.Lock()
		// drop by default.
		// If somehow the reject tailing rule is skipped,
		// this will introduced timeouts for processes
		// that request to access an non-authorized ip.
		outputPolicy := nftables.ChainPolicyDrop
		nc = firewallBackend.nft.AddChain(&nftables.Chain{
			Name:     firewallBackend.chainName,
			Table:    firewallBackend.table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &outputPolicy,
		})
		firewallBackend.Unlock()
	}
	firewallBackend.chain = nc

	firewallBackend.Lock()
	err = firewallBackend.nft.Flush()
	if err != nil {
		return nil, err
	}
	firewallBackend.Unlock()

	return firewallBackend, nil
}

func (f *FirewallBackend) getChain(c string) (*nftables.Chain, error) {
	f.Lock()
	defer f.Unlock()

	chains, err := f.nft.ListChains()
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
	defer f.Unlock()

	tables, err := f.nft.ListTables()
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

// AddRejectVerdict is responsible for appending a reject verdict at the end of the chain. If reject verdict
// is not a tailing verdict it will move it at the end by first creating a new reject verdict at the end of
// the chain and then deleting the existing one
func (f *FirewallBackend) AddRejectVerdict() error {
	rules, err := f.nft.GetRule(f.table, f.chain)
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
				if err != nil {
					return err
				}

				f.nft.DelRule(&nftables.Rule{
					Table:  f.table,
					Chain:  f.chain,
					Handle: r.Handle,
				})

				err = f.nft.Flush()
				if err != nil {
					return err
				}

				f.Unlock()
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
