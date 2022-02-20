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

	var resp *dns.Msg
	var question string
	var err error

	question = s.cache.Question(req)

	if isCached := s.cache.Exists(req); isCached {
		if hasExpired := s.cache.HasExpired(req); hasExpired {
			s.cache.Delete(req)
			s.fwdl.Debugf(infoCacheObjExpired, question)
			goto forwardUpstream
		}

		r := s.cache.Get(req)
		if r != nil {
			s.fwdl.Debugf(infoCacheObjFound, question)
			resp = r
			resp.Id = req.Id
			goto tellClient
		}

		s.fwdl.Errorf(errCacheFetch, question)
	}

	if isNXCached := s.cache.ExistsNX(req); isNXCached {
		if hasExpired := s.cache.HasExpiredNX(req); !hasExpired {
			s.fwdl.Debugf("[Cache] %s", question)
			resp = req
			goto tellClient
		}

		s.cache.DeleteNX(req)
		s.fwdl.Debugf(infoCacheObjExpired, question)
	}

forwardUpstream:
	resp, _, err = s.client.Exchange(req, s.fwdAddr)
	if err != nil {
		s.qErr(w, req, err)
		return
	}

	err = s.pushToCache(resp)
	if err != nil {
		s.fwdl.Error(err)
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
	s.cache.RegisterNX(req)
	dns.HandleFailed(w, req)
}

func (s *Server) pushToCache(msg *dns.Msg) error {
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
	if exists := s.cache.ExistsNX(msg); exists {
		if expired := s.cache.HasExpiredNX(msg); expired {
			ok := s.cache.RenewNX(msg)
			if !ok {
				return fmt.Errorf(errCacheCoulndNotRenew, s.cache.Question(msg))
			}
		}
		return nil
	}
	ok := s.cache.RegisterNX(msg)
	if !ok {
		return fmt.Errorf(errCacheRegister, s.cache.Question(msg))
	}
	return nil
}

func (s *Server) register(msg *dns.Msg) error {
	if exists := s.cache.Exists(msg); exists {
		if expired := s.cache.HasExpired(msg); expired {
			ok := s.cache.Renew(msg)
			if !ok {
				return fmt.Errorf(errCacheCoulndNotRenew, s.cache.Question(msg))
			}
		}
		return nil
	}
	ok := s.cache.Register(msg)
	if !ok {
		return fmt.Errorf(errCacheRegister, s.cache.Question(msg))
	}

	return nil
}
