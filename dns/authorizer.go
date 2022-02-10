package dns

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func (s *Server) handleRequest(resp *dns.Msg) error {
	dnsQuestions := []string{}
	for _, q := range resp.Question {
		dnsQuestions = append(
			dnsQuestions,
			fmt.Sprintf("Question: %s", q.Name),
		)
	}

	if resp.Rcode != dns.RcodeSuccess {
		s.fwl.Infof("[Not Handled] %s - Is this local?", strings.Join(dnsQuestions, " "))
		return nil
	}

	if len(resp.Answer) == 0 {
		s.fwl.Infof("[Blocked] %s", strings.Join(dnsQuestions, " "))
		return nil
	}

	for _, answer := range resp.Answer {
		if r, ok := answer.(*dns.A); ok {
			blacklisted, err := s.checkBlacklist(r.A.String())
			if err != nil {
				s.fwl.Error(err)
				continue
			}

			if blacklisted {
				s.fwl.Infof("[Blocked] %s Host: %s", strings.Join(dnsQuestions, " "), r.A.String())
				continue
			}

			if r.A.String() == "0.0.0.0" {
				s.fwl.Infof("[Blocked] %s", strings.Join(dnsQuestions, " "))
				continue
			}

			regOK := s.Cache.Register(r.A.String())
			if !regOK {
				s.Cache.Renew(r.A.String())
				s.fwl.Infof("[Already Authorized] %s Host: %s", strings.Join(dnsQuestions, " "), r.A.String())
				continue
			}

			err = s.fw.AddIPv4ToSetRule(s.authorizedSet, r.A.String())
			if err != nil {
				s.fwl.Error(err)
				continue
			}
			s.fwl.Infof("[Authorized] %s Hosts: [%s]", strings.Join(dnsQuestions, " "), r.A.String())
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
		}
	}

	return nil
}

func (s *Server) checkBlacklist(ip string) (bool, error) {
	// unsafe function, we are not checking string input for valid
	// ip address. We should add a check here
	for _, j := range s.blacklistHosts {
		if ip == j {
			return true, nil
		}
	}

	for _, j := range s.blacklistNetworks {
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
