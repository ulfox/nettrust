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

// NewResolved replaces current cache.resolved map with a new map
// by copying all the elements. We  this to free up memory, since
// the allocated memory by cache.resolved is that that the map had at
// its peak
func (c *Queries) NewResolved() {
	c.Lock()
	defer c.Unlock()

	newMap := make(map[string]Answered)

	for k, v := range c.resolved {
		newMap[k] = v
	}

	c.resolved = nil
	c.resolved = newMap
}

// NewNX replaces current cache.nx map with a new map
// by copying all the elements. See cache.NewResolved
// for additional information
func (c *Queries) NewNX() {
	c.Lock()
	defer c.Unlock()

	newMap := make(map[string]time.Time)

	for k, v := range c.nx {
		newMap[k] = v
	}

	c.nx = nil
	c.nx = newMap
}

// GetTTL return cache.ttl value
func (c *Queries) GetTTL() int {
	return c.ttl
}

// Question returns dns.Msg.Question[0].Name from a given dns message
func (c *Queries) Question(msg *dns.Msg) string {
	return strings.TrimSuffix(msg.Question[0].Name, ".")
}

// Exists (blocking) returns true if a question is in cache
func (c *Queries) Exists(q string) bool {
	c.Lock()
	defer c.Unlock()

	_, ok := c.resolved[q]

	return ok
}

// ExistsNX (blocking) returns true if a question is in NX cache
func (c *Queries) ExistsNX(q string) bool {
	c.Lock()
	defer c.Unlock()

	_, ok := c.nx[q]

	return ok
}

// HasExpired for checking if a specific question in cache has expired
func (c *Queries) HasExpired(s string) bool {
	if !c.Exists(s) {
		return true
	}

	c.Lock()
	defer c.Unlock()

	q := c.resolved[s]

	return time.Since(q.T) > time.Second*time.Duration(c.ttl)
}

// HasExpiredNX for checking if a specific question in NX cache has expired
func (c *Queries) HasExpiredNX(s string) bool {
	if !c.ExistsNX(s) {
		return true
	}

	c.Lock()
	defer c.Unlock()

	q := c.nx[s]

	return time.Since(q) > time.Second*time.Duration(c.ttl)
}

// Get for getting a cached question from the cache
func (c *Queries) Get(s string) *dns.Msg {
	if c.Exists(s) {
		return c.resolved[s].M
	}

	return nil
}

// Register (blocking) for adding a new question to cache
func (c *Queries) Register(s string, msg *dns.Msg) bool {
	if c.Exists(s) {
		return false
	}

	c.Lock()
	defer c.Unlock()

	c.resolved[s] = Answered{
		M: msg,
		T: time.Now(),
	}

	return true
}

// RegisterNX (blocking) for adding a new question to NX cache
func (c *Queries) RegisterNX(s string) bool {
	if c.ExistsNX(s) {
		return false
	}

	c.Lock()
	defer c.Unlock()

	c.nx[s] = time.Now()

	return true
}

// Renew (blocking) for updating ttl for a question in cache
func (c *Queries) Renew(s string, msg *dns.Msg) bool {
	if !c.Exists(s) {
		return c.Register(s, msg)
	}

	c.Lock()
	defer c.Unlock()

	e := c.resolved[s]

	e.T = time.Now()

	return true
}

// RenewNX (blocking) for updating a ttl for a question in NX cache
func (c *Queries) RenewNX(s string) bool {
	if !c.ExistsNX(s) {
		return c.RegisterNX(s)
	}

	c.Lock()
	defer c.Unlock()

	c.nx[s] = time.Now()

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
func (c *Queries) Delete(h string) {
	c.Lock()
	defer c.Unlock()
	delete(c.resolved, h)
}

// DeleteNX (blocking) for deleting a question from NX cache
func (c *Queries) DeleteNX(h string) {
	c.Lock()
	defer c.Unlock()
	delete(c.nx, h)
}
