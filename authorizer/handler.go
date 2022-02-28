package authorizer

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// HandleRequest for filtering dns respone requests
func (f *Authorizer) HandleRequest(resp *dns.Msg) error {
	if f.cache == nil {
		return fmt.Errorf(errNil)
	}

	question := resp.Question[0].Name

	if resp.Rcode == dns.RcodeNameError {
		f.fwl.Infof(infoNXDomain, question)
		return nil
	}

	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf(errRcode, question, resp.Rcode)
	}

	if len(resp.Answer) == 0 {
		if resp.Question[0].Qtype == dns.TypeAAAA {
			f.fwl.Infof(infoAuthIPv6Block, question)
			return nil
		}
		f.fwl.Infof(infoAuthBlock, question)
		return nil
	}

	if resp.Question[0].Qtype == dns.TypeA {
		for _, answer := range resp.Answer {
			if _, ok := answer.(*dns.CNAME); ok {
				// Nothing to do here for now. CNAME is not IP Address
				// this should not be a problem since usually CNAME
				// addresses are answered in the same query
				continue
			}

			r, ok := answer.(*dns.A)
			if !ok {
				f.fwl.Errorf(errInvalidReply, "TypeA", question)
				continue
			}

			err := f.authIPv4(question, r.A.String())
			if err != nil {
				f.fwl.Error(err)
			}
		}

		return nil
	}

	if resp.Question[0].Qtype == dns.TypeAAAA {
		for _, answer := range resp.Answer {
			if r, ok := answer.(*dns.AAAA); ok {
				// Not supported yet
				f.fwl.Warnf(warnIPv6Support, question, r.AAAA.String())
			}
		}

		return nil
	}

	if resp.Question[0].Qtype == dns.TypePTR {
		answerSlice := []string{}
		for _, answer := range resp.Answer {
			r, ok := answer.(*dns.PTR)
			if !ok {
				f.fwl.Errorf(errInvalidReply, "TypePTR", question)
				continue
			}
			answerSlice = append(answerSlice, r.Ptr)
		}

		if t := strings.Split(question, ".arpa")[0]; strings.HasSuffix(t, ".ip6") {
			f.fwl.Warnf(warnPTRIPv6, question, strings.Join(answerSlice, " "))
			return nil
		}

		// Split PTR Question BE IPv4 string
		revAddr := strings.Split(question, ".in-addr.arpa")[0]

		// Split BE IPv4 string into a slice
		revAddrSlice := strings.Split(revAddr, ".")
		addrSlice := []string{}

		// Convert to LE
		for i := len(revAddrSlice) - 1; i >= 0; i-- {
			addrSlice = append(addrSlice, revAddrSlice[i])
		}

		// Construct back IPv4 into LE
		addr := strings.Join(addrSlice, ".")
		f.fwl.Infof(infoPTRIPv4, question, addr, strings.Join(answerSlice, ""))

		err := f.authIPv4(question, addr)
		if err != nil {
			f.fwl.Error(err)
		}

		return nil
	}

	f.fwl.Warnf(warnNotSupportedQuery, resp.Question[0].Qtype, question)

	return nil
}

func (f *Authorizer) authIPv4(question, ip string) error {
	blacklisted, err := f.checkIPv4Blacklist(ip)
	if err != nil {
		return err
	}

	if blacklisted {
		f.fwl.Infof(infoAuthBlacklist, question, ip)
		return nil
	}

	if ip == "0.0.0.0" {
		f.fwl.Infof(infoAuthBlock, question)
		return nil
	}

	regOK := f.cache.Register(ip)
	if !regOK {
		f.cache.Renew(ip)
		f.fwl.Infof(infoAuthExists, question, ip)
		return nil
	}

	err = f.fw.AddIPv4ToSetRule(f.authorizedSet, ip)
	if err != nil {
		return err
	}
	f.fwl.Infof(infoAuth, question, ip)

	return nil
}

func (f *Authorizer) checkIPv4Blacklist(ip string) (bool, error) {
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
