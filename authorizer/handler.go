package authorizer

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func (f *Authorizer) HandleRequest(resp *dns.Msg) error {
	if f.cache == nil {
		return fmt.Errorf(ErrNil)
	}

	dnsQuestions := []string{}
	for _, q := range resp.Question {
		dnsQuestions = append(
			dnsQuestions,
			fmt.Sprintf("Question: %s", q.Name),
		)
	}

	if resp.Rcode != dns.RcodeSuccess {
		f.fwl.Infof("[Not Handled] %s - Is this local?", strings.Join(dnsQuestions, " "))
		return nil
	}

	if len(resp.Answer) == 0 {
		f.fwl.Infof("[Blocked] %s", strings.Join(dnsQuestions, " "))
		return nil
	}

	for _, answer := range resp.Answer {
		if r, ok := answer.(*dns.A); ok {
			blacklisted, err := f.checkBlacklist(r.A.String())
			if err != nil {
				f.fwl.Error(err)
				continue
			}

			if blacklisted {
				f.fwl.Infof("[Blocked] %s Host: %s", strings.Join(dnsQuestions, " "), r.A.String())
				continue
			}

			if r.A.String() == "0.0.0.0" {
				f.fwl.Infof("[Blocked] %s", strings.Join(dnsQuestions, " "))
				continue
			}

			regOK := f.cache.Register(r.A.String())
			if !regOK {
				f.cache.Renew(r.A.String())
				f.fwl.Infof("[Already Authorized] %s Host: %s", strings.Join(dnsQuestions, " "), r.A.String())
				continue
			}

			err = f.fw.AddIPv4ToSetRule(f.authorizedSet, r.A.String())
			if err != nil {
				f.fwl.Error(err)
				continue
			}
			f.fwl.Infof("[Authorized] %s Hosts: [%s]", strings.Join(dnsQuestions, " "), r.A.String())
		} else if _, ok := answer.(*dns.CNAME); ok {
			// Nothing to do here for now. CNAME is not IP Address
			// this should not be a problem since usually CNAME
			// addresses are answered in the same query
			continue
		} else if r, ok := answer.(*dns.AAAA); ok {
			// Not supported yet
			if r.AAAA.String() == "0.0.0.0" {
				continue
			}
		} else if r, ok := answer.(*dns.PTR); ok {
			f.fwl.Infof("[PTR] %s resolved to %s", strings.Join(dnsQuestions, " "), r.Ptr)
		}
	}

	return nil
}

func (f *Authorizer) checkBlacklist(ip string) (bool, error) {
	// unsafe function, we are not checking string input for valid
	// ip address. We should add a check here
	for _, j := range f.blacklistHosts {
		if ip == j {
			return true, nil
		}
	}

	for _, j := range f.blacklistNetworks {
		_, netj, err := net.ParseCIDR(j)
		if err != nil {
			return false, err
		}

		if netj.Contains(net.ParseIP(ip)) {
			return true, nil
		}
	}

	return false, nil
}
