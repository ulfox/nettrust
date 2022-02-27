# ToDo List

## Fix

- Conntrack activeHosts throws netfilter query error on MIPS64 SF
- DNS Cache slows queries (Observed on TPLink Archer C7). Local DNS queries that are not cached take more time compared
  when compared with the same queries without cache

## Improvements

- Check chains priority and ensure NetTrust Chain has high priority in the related table

## Features

- Cloud provider plugin
- Add option for TLS Client authendication
- Add eBPF filtering to allow NetTrust block packets before they enter the Kenrel network stack
- Add network namespace filtering option. This can be achieved by making the firewall backend an array and loop over each time a command is executed to handle multipe namespaces
- DNS listen strikes on many invalid/block requests
- Handle IPv6 also
- Add support for reverse queries, essentially whitelisting IPs if the DNS Authorizer returns a domain back to NetTrust
- Add metrics capabilities to monitor NetTrust
- Add network statistics (e.g. how many times a host was queried) to allow alerts/notifications on certain events
- Add DNSSec
- Add IPTables Support (iptables-legacy, iptables-nft)
- Add option to use a KV store for keeping host tracking information
- Use conntrack to check and react on connections that open and are not part of NetTrust whitelisted hosts
- Conntrack Hosts & ttl metrics
- Add option to handle A/AAA zones instead of forwarding all requests
- Add option to watch for /etc/resolv.conf changes and revert back to NetTrust listening address
- Add DNS Forward loadbalance option (to allow usage of more than 1 DNS server)
- Add debug logs

