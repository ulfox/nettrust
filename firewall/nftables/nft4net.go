package nftables

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func (f *FirewallBackend) getIPv4NetworkRule(cidr string) (*nftables.Rule, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	rules, err := f.nft.GetRule(f.table, f.chain)
	if err != nil {
		return nil, err
	}

	f.Lock()
	defer f.Unlock()

	for _, rule := range rules {
		for _, e := range rule.Exprs {
			cmp, ok := e.(*expr.Cmp)
			if !ok {
				continue
			}

			if net.IP(cmp.Data).String() != n.IP.String() {
				continue
			}

			goto checkBitwise
		}
		continue
	checkBitwise:
		for _, bw := range rule.Exprs {
			bitwise, ok := bw.(*expr.Bitwise)
			if !ok {
				continue
			}
			if hex.EncodeToString(bitwise.Mask) == n.Mask.String() {
				return rule, nil
			}
		}
	}

	return nil, fmt.Errorf("could not find network rule with cidr [%s]", cidr)
}

// AddIPv4NetworkRule for whitelisting an IPv4 network in the chain. Should be used on initial setup and
// sometimes for whitelisting new networks in the chain
func (f *FirewallBackend) AddIPv4NetworkRule(cidr string) error {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	_, err = f.getIPv4NetworkRule(cidr)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "could not find network rule with cidr") {
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
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           n.Mask,
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     n.IP,
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	return f.nft.Flush()
}

// DeleteIPv4NetworkRule for deleting a whitelisted network from the chain
func (f *FirewallBackend) DeleteIPv4NetworkRule(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	r, err := f.getIPv4NetworkRule(cidr)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "could not find network rule with cidr") {
			return err
		}
		return nil
	}

	f.Lock()
	defer f.Unlock()

	r.Chain = f.chain
	r.Table = f.table

	err = f.nft.DelRule(r)
	if err != nil {
		return err
	}
	return f.nft.Flush()
}
