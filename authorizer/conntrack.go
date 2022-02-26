package authorizer

import (
	"fmt"
	"strings"
)

// conntrackDump, not blocking for now. For now, we expect activeHosts to
// be read only by ttl checker and written only by this method
func (f *Authorizer) conntrackDump() (map[string]struct{}, error) {
	if f.conntrack == nil {
		return nil, fmt.Errorf(errNil)
	}

	df, err := f.conntrack.Dump()
	if err != nil {
		return nil, err
	}

	activeHosts := map[string]struct{}{}

	// This call is a bit slow on systems with a huge number of active connections, however it is a good
	// way to ensure that we get in the map hosts that are part of source or destination
	//
	// If this is reported to be too slow, then we should look for a better solution
	// The good thing is that this call is not blocking. The ttl checker may hang while waiting for
	// the activeHosts list, however during the wait, RequestHandler is free to call cache
	for _, j := range df {
		activeHosts[strings.Split(j.TupleOrig.IP.DestinationAddress.String(), ":")[0]] = struct{}{}
		activeHosts[strings.Split(j.TupleOrig.IP.SourceAddress.String(), ":")[0]] = struct{}{}
		activeHosts[strings.Split(j.TupleReply.IP.DestinationAddress.String(), ":")[0]] = struct{}{}
		activeHosts[strings.Split(j.TupleReply.IP.SourceAddress.String(), ":")[0]] = struct{}{}
	}

	return activeHosts, nil
}
