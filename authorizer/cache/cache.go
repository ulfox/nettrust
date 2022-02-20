package cache

import (
	"sync"
	"time"
)

// Authorized for storing Authorized DNS Hosts
type Authorized struct {
	sync.Mutex
	TTL   int
	Hosts map[string]time.Time
}

// NewCache creates a new empty cache
func NewCache(ttl int) *Authorized {
	return &Authorized{
		TTL:   ttl,
		Hosts: make(map[string]time.Time),
	}
}

// NewAuthMap replaces current cache.Hosts map with a new map
// by copying all the elements. We  this to free up memory, since
// the allocated memory by cache.Hosts is that that the map had at
// its peak
func (c *Authorized) NewAuthMap() {
	c.Lock()
	defer c.Unlock()

	newMap := make(map[string]time.Time)

	for k, v := range c.Hosts {
		newMap[k] = v
	}

	c.Hosts = nil
	c.Hosts = newMap
}

// Exists (blocking) returns true if a host is in cache
func (c *Authorized) Exists(h string) bool {
	c.Lock()
	defer c.Unlock()
	_, ok := c.Hosts[h]

	return ok
}

// Register (blocking) for adding a new host to cache
func (c *Authorized) Register(h string) bool {
	if c.Exists(h) {
		return false
	}

	c.Lock()
	defer c.Unlock()

	c.Hosts[h] = time.Now()

	return true
}

// Renew (blocking) for updating a hosts registration time in cache
func (c *Authorized) Renew(h string) {
	c.Lock()
	defer c.Unlock()

	c.Hosts[h] = time.Now()
}

// Expired (blocking) for returning all expired hosts. Returns empty slice if c.TTL is < 0
func (c *Authorized) Expired() []string {
	if c.TTL < 0 {
		return []string{}
	}

	c.Lock()
	defer c.Unlock()

	hosts := []string{}
	for h, t := range c.Hosts {
		if time.Since(t) > time.Second*time.Duration(c.TTL) {
			hosts = append(hosts, h)
		}
	}

	return hosts
}

// Delete (blocking) for deleting a host from cache
func (c *Authorized) Delete(h string) {
	c.Lock()
	defer c.Unlock()
	delete(c.Hosts, h)
}
