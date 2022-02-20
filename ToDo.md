# ToDo List

## Improvements

- Check chains priority and ensure NetTrust Chain has high priority in the related table
- Make nftable module more dynamic. Add DNAT & SNAT filtering. Add jump rules, enable logging
- Handle authorizer and dns cache maps differently. Currently the allocated memory on each map will be that of the map when it had the maximum number of elements during the runtime. This is not a memleak, but how maps work. However, NetTrust should be able to run on devices with limited memory, and due to that, we need to ensure that such devices will be able to free up memory after peaks

## Features

- Cloud provider plugin
- Add option for TLS Client authendication
- Add eBPF filtering to allow NetTrust block packets before they enter the Kenrel network stack
- Add network namespace filtering option. This can be achieved by making the firewall backend an array and loop over each time a command is executed to handle multipe namespaces
- DNS listen strikes on many invalid/block requests
- Handle IPv6 also
- Add support for reverse queries, essentially whitelisting IPs if the DNS Authorizer returns a domain back to NetTrust
- Add NAT Filtering to allow NetTrust to run as an intermediate (GW) server. Currently NetTrust filters only OUTPUT Hook from the Filtering table. NAT/PREROUTING should also be available soon
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

