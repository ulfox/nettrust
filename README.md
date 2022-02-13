# NetTrust: Dynamic Outbound Firewall Authorizer

NetTrust is a Dynamic Outbound Firewall Authorizer. It uses a DNS as a source of truth to allow/deny outbund requests

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

    ________________                             ____________                   ____________
   |                |     Query: example.com    |            |     Forward     |            |
   | Host Process A |=------------------------> |  NetTrust  |=--------------> | DNS Server |
   |________________|                           |____________|                 |____________|

```

In the above diagram queries are sent to NetTrust, and from there NetTrust forwards them to the DNS Server that either knows the question or has been configured to forward queries.


```bash

    ________________                             ____________                   ____________
   |                |     Query: example.com    |            |     Reply OK    |            |
   | Host Process A |=------------------------> |  NetTrust  | <--------------=| DNS Server |
   |________________|                           |____________|                 |____________|
            |                                          |
            |                                          |
            |                                          |
            |                                          |
            |                                          |         _____________
            |                                          |        |             |
            |                                          |=-----> |  Netfilter  |
            |                                                   |             |
            |                                                    -------------
     ______________                                                    |
    |              |          x.x.x.x is whitelisted                   |
    | OUTPUT HOOK  | <------------------------------------------------=|
    |______________|
```

Once NetTrust receives a query response, it checks if there are any answers (hosts resolved). If there are, it proceeds by updating firewall rules (e.g. nftables) in order to allow network access to the resolved hosts. If there is no answer, or if the answer is **0.0.0.0**, no action is taken. In all cases, the dns reply is sent back to the requestor process after a firewall decision has been made (if any).

### Authorized hosts TTL

NetTrust by default does not enable TTL on authorized hosts. The max authorized time a host can get is the time that NetTrust runs. Once NetTrust exits gracefully, it will clear the authorized hosts.

We can enable however TTL on authorized hosts. By adding a TTL, NetTrust will allow communication to that host for as long as TTL is set. Once a host is expired and no session is active (see Conntrack section below), it will be removed from the authorized list and will be expected by the process that wants to continue communication to resolve the host via the DNS again.

#### Conntrack: Session liveness and TTL

All sessions that have TTL enabled will be checked against two rules. The first rule is the TTL itself. If the host has not expired, nothing happens, if it has expired, then conntrack will be checked to ensure that no connection with the specific host is active. If a tuple contains the host, either in the src or dst, then the TTL will be renewed and the host will be checked again in the next expiration. If the host is not part of any conntrack connection, then the host will be removed from the cache and the firewall's authorized hosts set

```bash
     _______                                   _____________
    |       |        Get Expired Hosts        |             |
    | Cache |=------------------------------> | TTL Checker |
    |_______|                                 |_____________|
                                                     |
                                                     |
                                           __________|__________
                                          |                     |
                                          | Has host X Expired? |
                                          |_____________________|
                                                     |
                                                     | Yes
     _______________                       __________|___________                   ___________
    |               |               No    |                      |      Yes        |           |
    |  De-Authorize | <------------------=| Is connection active |=--------------> | Renew TTL |
    |_______________|                     |______________________|                 |___________|
                                                     |
                                                     | 
                                                     |
     ___________                                     |
    |           |    Get Active Connections          |
    | Conntrack |=---------------------------------> |
    |___________|
```

## Build

To build NetTrust, simply issue:

```bash
    go build -o nettrust cmd/nettrust.go
```

## Run NetTrust

Note: NetTrust needs to interact Netfilter, for that, it requires root access

To run NetTrust, issue `./nettrust  -fwd-addr "someIP:53" -listen-addr "127.0.0.1:53 -config config.json"`

- listen-addr is the listening address that NetTrust will listen and forward dns queries
- fwd-addr is the address of the DNS Server that NetTrust will use to resolve queries

Example output

```bash
INFO[2022-02-12T20:40:16+02:00] Starting UDP DNS Server                       Component="DNS Server" Stage=Init
INFO[2022-02-12T20:40:16+02:00] Starting TCP DNS Server                       Component="DNS Server" Stage=Init
INFO[2022-02-12T20:40:16+02:00] Starting                                      Component="[UDP] DNSServer" Stage=Init
INFO[2022-02-12T20:40:16+02:00] Starging                                      Component="[TCP] DNSServer" Stage=Init
# Some time later
INFO[2022-02-12T20:41:02+02:00] [Blocked] Question: example.com.   Component=Firewall Stage=Authorizer
INFO[2022-02-12T20:41:02+02:00] [Not Handled] Question: example.com.federation.local. - Is this local?  Component=Firewall Stage=Authorizer
INFO[2022-02-12T20:41:14+02:00] [PTR] Question: 247.1.168.192.in-addr.arpa. resolved to arph.federation.local.  Component=Firewall Stage=Authorizer
INFO[2022-02-12T20:41:36+02:00] [Blocked] Question: api.removedButWasSomeDomainHere.         Component=Firewall Stage=Authorizer
INFO[2022-02-12T20:41:37+02:00] [Blocked] Question: api.removedButWasSomeDomainHere.         Component=Firewall Stage=Authorizer
INFO[2022-02-12T20:41:38+02:00] [Blocked] Question: api.removedButWasSomeDomainHere.         Component=Firewall Stage=Authorizer
INFO[2022-02-12T20:41:41+02:00] [Blocked] Question: api.removedButWasSomeDomainHere.         Component=Firewall Stage=Authorizer
INFO[2022-02-12T20:41:49+02:00] [Blocked] Question: api.removedButWasSomeDomainHere.         Component=Firewall Stage=Authorizer
# Some time later when I did a git push
INFO[2022-02-12T21:19:30+02:00] [Authorized] Question: github.com. Hosts: [140.82.121.4]  Component=Firewall Stage=Authorizer
# Some time later when I did a git fetch
INFO[2022-02-12T21:41:54+02:00] [Already Authorized] Question: github.com. Host: 140.82.121.3  Component=Firewall Stage=Authorizer
```

The nftables authorized hosts set now looks like this

```bash
table ip net-trust {
	set whitelist {
		type ipv4_addr
		elements = { 127.0.0.1, 192.168.178.21 }
	}

	set authorized {
		type ipv4_addr
		elements = { xyz.xyz.xyz.xyz, xyz.xyz.xyz.xyz,
			     xyz.xyz.xyz.xyz, xyz.xyz.xyz.xyz,
			     xyz.xyz.xyz.xyz, xyz.xyz.xyz.xyz,
			     xyz.xyz.xyz.xyz, xyz.xyz.xyz.xyz,
			     xyz.xyz.xyz.xyz, xyz.xyz.xyz.xyz,
			     xyz.xyz.xyz.xyz, xyz.xyz.xyz.xyz,
			     xyz.xyz.xyz.xyz, 140.82.121.3 }
	}

	chain authorized-output {
		type filter hook output priority filter; policy drop;
		ip daddr 127.0.0.0/8 counter packets 563 bytes 48587 accept
		ip daddr 10.0.0.0/8 counter packets 0 bytes 0 accept
		ip daddr 172.16.0.0/12 counter packets 0 bytes 0 accept
		ip daddr 192.168.0.0/16 counter packets 273 bytes 20402 accept
		ip daddr 100.64.0.0/10 counter packets 0 bytes 0 accept
		ip daddr @whitelist accept
		ip daddr @authorized accept
		counter packets 23 bytes 2637 reject with icmp type net-unreachable
	}
}
```

Check options below for additional configuration

### NetTrust options

NetTrust accepts the follwoing options

```bash
Usage of ./bin/nettrust:
  -authorized-ttl int
    	Number of seconds a authorized host will be active before NetTrust expires it and expect a DNS query again (-1 do not expire)
  -config string
    	Path to config.json
  -do-not-flush-authorized-hosts
    	Do not clean up the authorized hosts list on exit. Use this together with do-not-flush-table to keep the NetTrust table as is on exit
  -do-not-flush-table
    	Do not clean up tables when NetTrust exists. Use this flag if you want to continue to deny communication when NetTrust has exited
  -firewall-type string
    	NetTrust firewall type (nftables is only supported for now)
  -fwd-addr string
    	NetTrust forward dns address
  -fwd-proto string
    	NetTrust dns forward protocol
  -fwd-tls
    	Enable DoT. This expects that forward dns address supports DoT and fwd-proto is tcp
  -fwd-tls-cert string
    	path to certificate that will be used to validate forward dns hostname. If you do not set this, the the host root CAs will be used
  -listen-addr string
    	NetTrust listen dns address
  -listen-cert string
    	path to certificate that will be used by the TCP DNS Service to serve DoT
  -listen-cert-key string
    	path to the private key that will be used by the TCP DNS Service to serve DoT
  -listen-tls
    	Enable tls listener, tls listener works only with the TCP DNS Service, UDP will continue to serve in plaintext mode
  -ttl-check-ticker int
    	How often NetTrust should check the cache for expired authorized hosts (Checking is blocking, do not put small numbers)
  -whitelist-loopback
    	Loopback network space 127.0.0.0/8 will be whitelisted (default true)
  -whitelist-private
    	If 10.0.0.0/8, 172.16.0.0/16, 192.168.0.0/16, 100.64.0.0/10 will be whitelisted (default true)
```

#### Config options

You can also use a json config to set options.

```json
{
    "whitelist": {
        "networks": [],
        "hosts": []
    },
    "blacklist": {
        "networks": [],
        "hosts": []
    },
    "fwdAddr": "192.168.178.21:53", // Example address of local dns server
    "fwdProto": "udp",
    "fwdCaCert": "",
    "fwdTLS": false,

    "listenAddr": "127.0.0.1:53",
    "firewallType": "nftables",

    "whitelistLoEnabled": true,
    "whitelistPrivateEnabled": true,
    "ttl": -1,
    "ttlInterval": 30,
    "doNotFlushTable": false, // Set this to true if you want to keep the rules and the chain when NetTrust has stopped
    "doNotFlushAuthorizedHosts": false
}
```

**Note**: Config file options have lower priority from flag options. For example, if you start NetTrust with `-fwd-tls` and you set `fwdTLS: false` in the config, NetTrust will use tls since flags have the highest priority 

##### Do Not Flush Table on Exit

**Note**: As you can imagine, with this option set to true, you will not be able to access any host that is not part of a whitelisted option (hosts, networks). If you enabled this option and you wish to revert back, simply start NetTrust again with this option set to false and then exit

If you wish to keep the table's content on NetTrust exit, then pass either `-do-not-flush-table` via flags or `doNotFlushTable: true` via config. NetTrust on exit will clear only the authorized set, that is the set that is populated via resolved hosts.

It will keep:

- The chain with the default policy to drop
- The whitelisted hosts
- The whitelisted networks
- Final reject verdict

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

Blacklisting instructs NetTrust to skip hosts that match the hostlist or are part of the network. Skipping is essentially blackist since chain's tailing policy is reject and chain's default policy is drop


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

#### NFTables clean ruleset manually

If you need to remove NetTrust rules and chains manually, then please follow this section

##### Remove rule

To remove a rule, first get the rule's handle number

```bash
sudo nft list table net-trust -a
```

```bash
table ip net-trust { # handle 5
	set whitelist { # handle 7
		type ipv4_addr
		elements = { 127.0.0.1, 192.168.178.21 }
	}

	set authorized { # handle 9
		type ipv4_addr
		elements = { 140.82.121.4 }
	}

	chain authorized-output { # handle 129
		type filter hook output priority filter; policy drop;
		ip daddr 127.0.0.0/8 counter packets 2174 bytes 196333 accept # handle 130
		ip daddr 10.0.0.0/8 counter packets 0 bytes 0 accept # handle 131
		ip daddr 172.16.0.0/12 counter packets 0 bytes 0 accept # handle 132
		ip daddr 192.168.0.0/16 counter packets 105 bytes 8793 accept # handle 133
		ip daddr 100.64.0.0/10 counter packets 0 bytes 0 accept # handle 134
		ip daddr @whitelist accept # handle 135
		ip daddr @authorized accept # handle 136
		counter packets 90 bytes 8380 reject with icmp type net-unreachable # handle 137
	}
}
```

To remove rule `ip daddr 100.64.0.0/10 counter packets 0 bytes 0 accept # handle 134` as an example, issue

```bash
sudo nft delete rule net-trust authorized-output handle 134
```

##### Remove all rules from all chains in the table

To remove all rules from all chains, issue

```bash
sudo nft 'flush table net-trust'
```
