# NetTrust: Dynamic Firewall

NetTrust is a Dynamic Firewall Authorizer. It uses a DNS as a source of truth to allow/deny outbund requests

## Overview

The ideas is that we want to grant network access only to networks or hosts that we trust. Trusted networks and hosts are whitelisted in Output Netfilter Hook, while all others are rejected.

To increase security or privacy, we usually want to block outbound traffic to:

- Blocked DNS Queries
- Direct Network Communication (Static IP, no Query made)

For the first item in the list, this is known as DNS Black hole and is a secure way to narrow down network communication only to trusted domains. However, not all processes (or javascript functions for example) use DNS Queries. There are many who use static IPs to communicate with the outside world. For example, a javascript function could dynamically fetch a list of hosts during render and forward traffic to them. For such case, DNS Blackholes are worethless.

Firewalls normally allow outbound access to all hosts but restrict inbound access to a selected few

```bash
    _________                                           _____________________
   |         |   Direct Communication IPv4: x.x.x.x    |                     |
   | Process |=--------------------------------------> | OUTBOUND: Allow All |
   |_________|                                         |_____________________|
        |
        |                                               _____________________________
        |                                              |                             |
        |<--------------------------------------------=| INBOUND: Few or Established |
                                                       |_____________________________|

```

The allow all to public but filter inbound works well with servers. There we trust the services that we run and we control components in a more strict way

But what happens when we want to filter and increase security on hosts that are not as restricted as servers or on hosts that may do many things, like personal computers. We install packages often, visit different websites which exposes us to different kind of tracking (telemetries, etc) and risks (hostile apps, bad javascript functions sending traffic to hosts we can not easilly stop)

The problem here is is that it is hard to filter all good hosts due to:

- big number of public IPs. The total number of IPv4 addresses may be small for the world, but is really huge to filter it in a list
- hosts usually change IPs, which makes the management of a whitelist even harder

A work around this issue (up to a way, because as always everything has its weaknesses), is to use DNS for traffic authorization.

### DNS Authorizer

DNS Authorizers are normal DNS hosts that we trust a lot. For example a local DNS service that we have configured to blacklist certain domains, or block all except some domains

With DNS Authorizer we can:

- Use them to filter our unwanted domains   (most common, needs a list of bad hosts)
- Use them to filter in only wanted domains (most secure, needs a lot more work    )

By using a DNS Authorizer we have the pros of a DNS Blackhole + easy filtering of IPs. All we need, is to block all outbound traffic and then allow only the traffic that DNS answers in the queries

This is how NetTrust works. It is small dns proxy with Netfilter management capabilities.

```bash

    ________________                         ____________                   ____________
   |                |     Query: x.x.x.x    |            |     Forward     |            |
   | Host Process A |=--------------------> |  NetTrust  |=--------------> | DNS Server |
   |________________|                       |____________|                 |____________|

```

In the above diagram queries are sent to NetTrust, and from there NetTrust forwards them to the DNS Server that either knows the question or has been configured to forward queries.


```bash

    ________________                         ____________                   ____________
   |                |     Query: x.x.x.x    |            |     Reply OK    |            |
   | Host Process A |=--------------------> |  NetTrust  | <--------------=| DNS Server |
   |________________|                       |____________|                 |____________|
            |                                      |
            |                                      |
            |                                      |
            |                                      |
            |                                      |         _____________
            |                                      |        |             |
            |                                      |=-----> |  Netfilter  |
            |                                               |             |
            |                                                -------------
     ______________                                                |
    |              |          x.x.x.x is whitelisted               |
    | OUTPUT HOOK  | <--------------------------------------------=|
    |______________|
```

Once NetTrust receives a query response, it checks if there are any answers (hosts resolved). If there are, it proceeds by updating firewall rules (e.g. nftables) in order to allow network access to the resolved hosts. If there is no answer, or if the answer is **0.0.0.0**, no action is taken. In all cases, the dns reply is sent back to the requestor process after a firewall decision has been made (if any).

## Build

To build NetTrust, simply issue:

```bash
    go build -o nettrust
```

## Run NetTrust

Note: NetTrust needs to interact Netfilter, for that, it requires root access

To run NetTrust, issue `./nettrust  -fwd-addr "someIP:53" -listen-addr "127.0.0.1:53"`

- listen-addr is the listening address that NetTrust will listen and forward dns queries
- fwd-addr is the address of the DNS Server that NetTrust will use to resolve queries

### NetTrust options

NetTrust accepts the follwoing options

```bash
  -firewall-type string
    	NetTrust firewall type (nftables is only supported for now) (default "nftables")
  -fwd-addr string
    	NetTrust forward dns address
  -listen-addr string
    	NetTrust listen dns address
  -whitelist-loopback
    	Loopback network space 127.0.0.0/8 will be whitelisted (default true)
  -whitelist-private
    	If 10.0.0.0/8, 172.16.0.0/16, 192.168.0.0/16, 100.64.0.0/10 will be whitelisted (default true)
  -authorized-ttl int
    	Number of seconds a authorized host will be active before NetTrust expires it and expect a DNS query again (-1 do not expire) (default -1)
```

### NetTrust ENV/Config whitelist / blacklist

Note: Whitelisting, blacklisting should be done automatically via DNS proxy. This option should be used if you want to add custom entries

We can add hosts or networks to whitelist or blacklist by using

- Environmental variables
- config file `config.json`

Note: Networks are evaluated first in the chain managed by NetTrust (for additional info, see NFTables Overview section at the end of this Readme)

#### Using Environmental variables

Whitelist a host by exporting `NET_TRUST_WHITELIST_HOSTS_<someHost>=someIP`

```bash
export NET_TRUST_WHITELIST_HOSTS_CUSTOM=192.168.1.1
```

Whitelist a network by exporting `NET_TRUST_WHITELIST_NETWORK_<someNetworkName>=someNetwork`

```bash
export NET_TRUST_WHITELIST_NETWORK_HOME=192.168.1.0/24
```

Note: blacklisting via env is not yet supported. Check config section in the next section to add blacklists

#### Using Config file

Use `config.json` to whitelist or blacklist hosts and networks

Note: This is expected to be in the root directory that hosts NetTrust binary

```bash
{
    "whitelist": {
        "networks": [],
        "hosts": []
    },
    "blacklist": {
        "networks": [],
        "hosts": []
    }
}
```

### NFTables chain overview

NetTrust creates a table called `net-trust` and a chain called `authorized`. Inside the chain it also creates two sets

- whitelist: populated by whitelisted hosts during init of NetTrust. This set should stay static during the lifetime of NetTrust (or unless new hosts are whitelisted)
- authorized: this set is used to add authorized hosts. If TTL is set to `-1` then this set should only grow during the lifetime of NetTrust and emptied on exit (we empty to ensure we do not forget whitelisted hosts behind)

Example of a populated table and chain. Here 127.0.0.1 and 192.168.178.21 are redundant since we whitelisted the networks that contain them, but were added because 127.0.0.1 was the listening address of NetTrust dns proxy and 192.168.178.21 is the IP of a local DNS Black hole. We always whitelist listening address and forward address to ensure that NetTrust will work without issues for cases where NetTrust is started with `-whitelist-private=false`

```bash
table ip net-trust {
	set whitelist {
		type ipv4_addr
		elements = { 127.0.0.1, 192.168.178.21 }
	}

	set authorized {
		type ipv4_addr
	}

	chain authorized-output {
		type filter hook output priority filter; policy drop;
		ip daddr 127.0.0.0/8 counter packets 2389 bytes 469802 accept
		ip daddr 10.0.0.0/8 counter packets 0 bytes 0 accept
		ip daddr 172.16.0.0/12 counter packets 0 bytes 0 accept
		ip daddr 192.168.0.0/16 counter packets 807 bytes 66255 accept
		ip daddr 100.64.0.0/10 counter packets 0 bytes 0 accept
		ip daddr @whitelist accept 
		ip daddr @authorized accept
		counter packets 14 bytes 1370 reject with icmp type net-unreachable
	}
}
```

As you may have noticed, there is no blacklist entry in the chain or in any set. This is because NetTrust uses deny all except firewall implementation. Blacklists are all hosts that are not resolved by the DNS Authority and the hosts added manually via the config file or env vars. The blacklisting is taking place in the DNS Proxy handler, there we check any returned results by the DNS Authority and skip them if they match a blacklist rule

