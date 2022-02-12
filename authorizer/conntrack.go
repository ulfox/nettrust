package authorizer

import (
	"strings"

	"github.com/ti-mo/conntrack"
)

// conntrackDump, not blocking for now. We may consider making this blocking to ensure that
// f.activeHosts are protected from concurrent writes. For now, we expect f.activeHosts to
// be read only by ttl checker and written only by this method
func (f *Authorizer) conntrackDump() (map[string]bool, error) {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return nil, err
	}

	df, err := c.Dump()
	if err != nil {
		return nil, err
	}

	activeHosts := map[string]bool{}

	// This call is a bit slow on systems with a huge number of active connections, however it is a good
	// way to ensure that we get in the map hosts that are part of source or destination
	//
	// If this is reported to be too slow, then we should look for a better solution
	// The good thing is that this call is not blocking. The ttl checker may hang while waiting for
	// the activeHosts list, however during the wait, RequestHandler is free to call cache
	for _, j := range df {
		activeHosts[strings.Split(j.TupleOrig.IP.DestinationAddress.String(), ":")[0]] = true
		activeHosts[strings.Split(j.TupleOrig.IP.SourceAddress.String(), ":")[0]] = true
		activeHosts[strings.Split(j.TupleReply.IP.DestinationAddress.String(), ":")[0]] = true
		activeHosts[strings.Split(j.TupleReply.IP.SourceAddress.String(), ":")[0]] = true
	}

	return activeHosts, nil
}
