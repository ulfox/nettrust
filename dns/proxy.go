package dns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func (s *Server) fwd(w dns.ResponseWriter, req *dns.Msg, fn func(resp *dns.Msg) error) {
	if len(req.Question) == 0 {
		s.qErr(w, req, fmt.Errorf(errQuery))
		return
	}

	if len(req.Question) > 1 {
		dns.HandleFailed(w, req)
		questions := []string{}

		for _, j := range req.Question {
			questions = append(questions, j.Name)
		}

		s.fwdl.Errorf(errManyQuestions, strings.Join(questions, " "))
		return
	}

	question := s.cache.Question(req)

	if s.checkDomainBlacklist(question) {
		dns.HandleFailed(w, req)
		s.fwdl.Infof(infoDomainBlacklist, question)
		return
	}

	var resp *dns.Msg
	var err error

	if s.cache.GetTTL() <= 0 {
		goto forwardUpstream
	}

	// We need to handle IPv6 cache differently
	// Maybe a new cache or appening a string to
	// keep IPv6 records apart from IPv4
	if req.Question[0].Qtype == dns.TypeAAAA {
		goto forwardUpstream
	}

	if isCached := s.cache.Exists(question); isCached {
		if hasExpired := s.cache.HasExpired(question); hasExpired {
			s.cache.Delete(question)
			s.fwdl.Debugf(infoCacheObjExpired, question)
			goto forwardUpstream
		}

		r := s.cache.Get(question)
		if r != nil {
			s.fwdl.Debugf(infoCacheObjFound, question)
			resp = r
			resp.Id = req.Id
			goto tellClient
		}

		s.fwdl.Errorf(errCacheFetch, question)
	}

	if isNXCached := s.cache.ExistsNX(question); isNXCached {
		if hasExpired := s.cache.HasExpiredNX(question); !hasExpired {
			s.fwdl.Debugf(infoCacheObjFoundNil, question)
			resp = req
			goto tellClient
		}

		s.cache.DeleteNX(question)
		s.fwdl.Debugf(infoCacheObjExpired, question)
	}

forwardUpstream:
	resp, _, err = s.client.Exchange(req, s.fwdAddr)
	if err != nil {
		s.qErr(w, req, err)
		return
	}

	if s.cache.GetTTL() > 0 {
		err = s.pushToCache(resp)
		if err != nil {
			s.fwdl.Error(err)
		}
	}

tellClient:
	err = fn(resp)
	if err != nil {
		s.qErr(w, req, err)
		return
	}

	err = w.WriteMsg(resp)
	if err != nil {
		s.qErr(w, req, err)
	}
}

func (s *Server) qErr(w dns.ResponseWriter, req *dns.Msg, err error) {
	s.fwdl.Error(err)
	s.cache.RegisterNX(s.cache.Question(req))
	dns.HandleFailed(w, req)
}

func (s *Server) pushToCache(msg *dns.Msg) error {
	// Do not register IPv6 (see commend at line ~43 for additional info)
	if msg.Question[0].Qtype == dns.TypeAAAA {
		return nil
	}

	if len(msg.Answer) == 0 {
		return s.registerNX(msg)
	}

	if len(msg.Answer) == 1 {
		if q4, ok := msg.Answer[0].(*dns.A); ok {
			if q4.A.String() == "0.0.0.0" {
				return s.registerNX(msg)
			}
		}

		if q6, ok := msg.Answer[0].(*dns.AAAA); ok {
			if q6.AAAA.String() == "::" {
				return s.registerNX(msg)
			}
		}
	}

	return s.register(msg)
}

func (s *Server) registerNX(msg *dns.Msg) error {
	q := s.cache.Question(msg)

	if exists := s.cache.ExistsNX(q); exists {
		if expired := s.cache.HasExpiredNX(q); expired {
			ok := s.cache.RenewNX(q)
			if !ok {
				return fmt.Errorf(errCacheCoulndNotRenew, q)
			}
		}
		return nil
	}

	ok := s.cache.RegisterNX(q)
	if !ok {
		return fmt.Errorf(errCacheRegister, q)
	}
	return nil
}

func (s *Server) register(msg *dns.Msg) error {
	q := s.cache.Question(msg)

	if exists := s.cache.Exists(q); exists {
		if expired := s.cache.HasExpired(q); expired {
			ok := s.cache.Renew(q, msg)
			if !ok {
				return fmt.Errorf(errCacheCoulndNotRenew, q)
			}
		}
		return nil
	}

	ok := s.cache.Register(q, msg)
	if !ok {
		return fmt.Errorf(errCacheRegister, q)
	}

	return nil
}

func (s *Server) checkDomainBlacklist(d string) bool {
	_, ok := s.domainBlacklist[d]
	return ok
}
