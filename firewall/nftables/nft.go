package nftables

import (
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

func (f *FirewallBackend) createChainInputWithEstablished(table *nftables.Table, chain *nftables.Chain) error {
	// ip filter INPUT
	// [ ct load state => reg 1 ]
	// [ bitwise reg 1 = (reg=1 & 0x00000006 ) ^ 0x00000000 ]
	// [ cmp neq reg 1 0x00000000 ]
	// [ counter pkts 0 bytes 0 ]
	// [ immediate reg 0 accept ]

	f.Lock()
	rules, err := f.nft.GetRule(table, chain)
	if err != nil {
		return err
	}
	f.Unlock()

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
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x06, 0x00, 0x00, 0x00},
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	err = f.nft.Flush()
	if err != nil {
		return err
	}

	// ip filter INPUT
	// [ meta load iifname => reg 1 ]
	// [ cmp eq reg 1 0x00006f6c 0x00000000 0x00000000 0x00000000 ]
	// [ immediate reg 0 accept ]

	f.nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Register: 1,
				Key:      expr.MetaKeyIIFNAME,
			},
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
