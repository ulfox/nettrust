package queries

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Answered for storing dns replies with TTL
type Answered struct {
	M *dns.Msg
	T time.Time
}

// Queries for storing dns answers
type Queries struct {
	sync.Mutex
	ttl      int
	resolved map[string]Answered
	nx       map[string]time.Time
}

// NewCache creates a new empty cache
func NewCache(ttl int) *Queries {
	return &Queries{
		ttl:      ttl,
		resolved: make(map[string]Answered),
		nx:       make(map[string]time.Time),
	}
}

// Question returns dns.Msg.Question[0].Name from a given dns message
func (c *Queries) Question(msg *dns.Msg) string {
	return strings.TrimSuffix(msg.Question[0].Name, ".")
}

// Exists (blocking) returns true if a question is in cache
func (c *Queries) Exists(msg *dns.Msg) bool {
	c.Lock()
	defer c.Unlock()

	_, ok := c.resolved[c.Question(msg)]

	return ok
}

// ExistsNX (blocking) returns true if a question is in NX cache
func (c *Queries) ExistsNX(msg *dns.Msg) bool {
	c.Lock()
	defer c.Unlock()

	_, ok := c.nx[c.Question(msg)]

	return ok
}

// HasExpired for checking if a specific question in cache has expired
func (c *Queries) HasExpired(msg *dns.Msg) bool {
	if !c.Exists(msg) {
		return true
	}

	c.Lock()
	defer c.Unlock()

	q := c.resolved[c.Question(msg)]

	return time.Since(q.T) > time.Second*time.Duration(c.ttl)
}

// HasExpiredNX for checking if a specific question in NX cache has expired
func (c *Queries) HasExpiredNX(msg *dns.Msg) bool {
	if !c.ExistsNX(msg) {
		return true
	}

	c.Lock()
	defer c.Unlock()

	q := c.nx[c.Question(msg)]

	return time.Since(q) > time.Second*time.Duration(c.ttl)
}

// Get for getting a cached question from the cache
func (c *Queries) Get(msg *dns.Msg) *dns.Msg {
	if c.Exists(msg) {
		return c.resolved[c.Question(msg)].M
	}

	return nil
}

// Register (blocking) for adding a new question to cache
func (c *Queries) Register(msg *dns.Msg) bool {
	if c.Exists(msg) {
		return false
	}

	c.Lock()
	defer c.Unlock()

	c.resolved[c.Question(msg)] = Answered{
		M: msg,
		T: time.Now(),
	}

	return true
}

// RegisterNX (blocking) for adding a new question to NX cache
func (c *Queries) RegisterNX(msg *dns.Msg) bool {
	if c.ExistsNX(msg) {
		return false
	}

	c.Lock()
	defer c.Unlock()

	c.nx[c.Question(msg)] = time.Now()

	return true
}

// Renew (blocking) for updating ttl for a question in cache
func (c *Queries) Renew(msg *dns.Msg) bool {
	if !c.Exists(msg) {
		return c.Register(msg)
	}

	c.Lock()
	defer c.Unlock()

	e := c.resolved[c.Question(msg)]

	e.T = time.Now()

	return true
}

// RenewNX (blocking) for updating a ttl for a question in NX cache
func (c *Queries) RenewNX(msg *dns.Msg) bool {
	if !c.ExistsNX(msg) {
		return c.RegisterNX(msg)
	}

	c.Lock()
	defer c.Unlock()

	c.nx[c.Question(msg)] = time.Now()

	return true
}

// ExpiredQueries (blocking) for returning all expired questions. Returns empty slice if c.ttl is < 0
func (c *Queries) ExpiredQueries() []string {
	if c.ttl < 0 {
		return []string{}
	}

	c.Lock()
	defer c.Unlock()

	questions := []string{}
	for h, q := range c.resolved {
		if time.Since(q.T) > time.Second*time.Duration(c.ttl) {
			questions = append(questions, h)
		}
	}

	return questions
}

// ExpiredMXQueries (blocking) for returning all expired NX questions. Returns empty slice if c.ttl is < 0
func (c *Queries) ExpiredMXQueries() []string {
	if c.ttl < 0 {
		return []string{}
	}

	c.Lock()
	defer c.Unlock()

	questions := []string{}
	for h, q := range c.nx {
		if time.Since(q) > time.Second*time.Duration(c.ttl) {
			questions = append(questions, h)
		}
	}

	return questions
}

// Delete (blocking) for deleting a question from cache
func (c *Queries) Delete(msg *dns.Msg) {
	c.Lock()
	defer c.Unlock()
	delete(c.resolved, c.Question(msg))
}

// DeleteNX (blocking) for deleting a question from NX cache
func (c *Queries) DeleteNX(msg *dns.Msg) {
	c.Lock()
	defer c.Unlock()
	delete(c.nx, c.Question(msg))
}
