package nftables

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func (f *FirewallBackend) getIPv4Rule(ip string) (*nftables.Rule, error) {
	f.Lock()
	rules, err := f.nft.GetRule(f.table, f.chain)
	f.Unlock()

	if err != nil {
		return nil, err
	}

	for _, rule := range rules {
		for _, e := range rule.Exprs {
			cmp, ok := e.(*expr.Cmp)
			if !ok {
				continue
			}
			if net.IP(cmp.Data).String() == ip {
				return rule, nil
			}
		}
	}

	return nil, fmt.Errorf(errNotSuchIPv4AddrRule, ip)
}

// AddIPv4Rule for adding IPv4 rules in the chain, should never be used after initial chain setup
func (f *FirewallBackend) AddIPv4Rule(ip string) error {
	netIP := net.ParseIP(ip).To4()
	if netIP == nil {
		return fmt.Errorf(errNotValidIPv4Addr, ip)
	}

	_, err := f.getIPv4Rule(ip)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "could not find rule with ip") {
			return err
		}
	} else {
		return nil
	}

	f.Lock()
	defer f.Unlock()

	f.nft.AddRule(&nftables.Rule{
		Table: f.table,
		Chain: f.chain,
		Exprs: []expr.Any{
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				Len:           4,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     netIP,
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	return f.nft.Flush()
}

// DeleteIPv4Rule for deleting an IPv4 rule from the chain
func (f *FirewallBackend) DeleteIPv4Rule(ip string) error {
	netIP := net.ParseIP(ip).To4()
	if netIP == nil {
		return fmt.Errorf(errNotValidIPv4Addr, ip)
	}

	r, err := f.getIPv4Rule(ip)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "could not find rule with ip") {
			return err
		}
		return nil
	}

	r.Chain = f.chain
	r.Table = f.table

	f.Lock()
	defer f.Unlock()

	err = f.nft.DelRule(r)
	if err != nil {
		return err
	}
	return f.nft.Flush()
}
