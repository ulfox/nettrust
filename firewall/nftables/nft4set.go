package nftables

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func (f *FirewallBackend) getIPv4Set(n string) (*nftables.Set, error) {
	f.Lock()
	set, err := f.nft.GetSetByName(f.table, n)
	f.Unlock()

	if err != nil {
		return nil, err
	}

	return set, nil
}

func (f *FirewallBackend) getIPv4SetRule(n string) (*nftables.Rule, error) {
	f.Lock()
	rules, err := f.nft.GetRule(f.table, f.chain)
	f.Unlock()

	if err != nil {
		return nil, err
	}

	for _, rule := range rules {
		for _, e := range rule.Exprs {
			lookup, ok := e.(*expr.Lookup)
			if !ok {
				continue
			}

			if lookup.SetName != n {
				continue
			}

			return rule, nil
		}
	}

	return nil, fmt.Errorf(errNoSuchIPv4SetRule, n)
}

// GetIPv4AuthorizedHosts return a slice of all hosts from a set
func (f *FirewallBackend) GetIPv4AuthorizedHosts(s string) ([]net.IP, error) {
	set, err := f.getIPv4Set(s)
	if err != nil {
		return nil, err
	}

	f.Lock()
	elements, err := f.nft.GetSetElements(set)
	f.Unlock()

	if err != nil {
		return nil, err
	}

	var hosts []net.IP

	for _, e := range elements {
		hosts = append(hosts, e.Key)
	}

	return hosts, nil
}

// AddIPv4Set for adding a new IPv4 set in the chain
func (f *FirewallBackend) AddIPv4Set(n string) error {
	_, err := f.getIPv4Set(n)
	if err == nil {
		return nil
	}

	f.Lock()
	defer f.Unlock()

	set := &nftables.Set{
		Name:      n,
		Anonymous: false,
		Interval:  false,
		Table:     f.table,
		KeyType:   nftables.TypeIPAddr,
	}
	err = f.nft.AddSet(set, []nftables.SetElement{})
	if err != nil {
		return err
	}

	return f.nft.Flush()
}

// AddIPv4SetRule for adding a whitelist rule in the chain for a specific IPv4 set
func (f *FirewallBackend) AddIPv4SetRule(n string) error {
	set, err := f.getIPv4Set(n)
	if err != nil {
		return err
	}

	_, err = f.getIPv4SetRule(n)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "could not find set rule with name") {
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
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        set.Name,
				SetID:          set.ID,
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	return f.nft.Flush()
}

// AddIPv4ToSetRule for adding a new IPv4 host in a set
func (f *FirewallBackend) AddIPv4ToSetRule(n, ip string) error {
	set, err := f.getIPv4Set(n)
	if err != nil {
		return err
	}

	netIP := net.ParseIP(ip).To4()
	if netIP == nil {
		return fmt.Errorf(errNotValidIPv4Addr, ip)
	}

	f.Lock()
	defer f.Unlock()

	err = f.nft.SetAddElements(
		set,
		[]nftables.SetElement{
			{
				Key: netIP.To4(),
			},
		},
	)
	if err != nil {
		return err
	}

	return f.nft.Flush()
}

// DeleteIPv4FromAuthorizedList for deleting an IPv4 host from a set
func (f *FirewallBackend) DeleteIPv4FromAuthorizedList(n, ip string) error {
	set, err := f.getIPv4Set(n)
	if err != nil {
		return err
	}

	netIP := net.ParseIP(ip).To4()
	if netIP == nil {
		return fmt.Errorf(errNotValidIPv4Addr, ip)
	}

	f.Lock()
	defer f.Unlock()

	err = f.nft.SetDeleteElements(
		set,
		[]nftables.SetElement{
			{
				Key: netIP.To4(),
			},
		},
	)
	if err != nil {
		return err
	}

	return f.nft.Flush()
}
