# ToDo List

## Improvements

- Check chains priority and ensure NetTrust Chain has high priority in the related table

## Features

- Add inbound rules to deny all except established / related connections (we might want to skip this since NetTrust is meant to filter outbound traffic mostly, but I am adding it here to track it in case we want to add some kind of default deny inbound rules on cases were no firewall rules exist at all)
- DNS listen strikes on many invalid/block requests
- Handle IPv6 also
- Add support for reverse queries, essentially whitelisting IPs if the DNS Authorizer returns a domain back to NetTrust
- Add NAT Filtering to allow NetTrust to as an intermediate (GW) server. Currently NetTrust filters only OUTPUT Hook from the Filtering table. NAT/PREROUTING should also be available soon
- Add metrics capabilities to monitor NetTrust
- Add network statistics (e.g. how many times a host was queried) to allow alerts/notifications on certain events
- Add DNSSec
- Add IPv6 Filtering
- Add IPTables Support (iptables-legacy, iptables-nft)
- Add option to use a KV store for keeping host tracking information
- Use conntrack to check connection info (for example, expire a whitelisted hosts sooner if the connection has been terminated)
- Use conntrack to check and react on connections that open and are not part of NetTrust whitelisted hosts
- Conntrack Hosts & ttl metrics
- Add option to handle A/AAA zones instead of forwarding all requests
- Add option to watch for /etc/resolv.conf changes and revert back to NetTrust listening address
- Add DNS Forward loadbalance option (to allow usage of more than 1 DNS server)
- Add debug logs
