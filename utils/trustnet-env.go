package utils

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"strings"
)

// NetTrust for reading either NET_TRUST env into a map or a config file into a map
type NetTrust struct {
	Whitelist struct {
		Networks []string `json:"networks"`
		Hosts    []string `json:"hosts"`
	} `json:"whitelist"`
	Blacklist struct {
		Networks []string `json:"networks"`
		Hosts    []string `json:"hosts"`
	} `json:"blacklist"`
	Env                               map[string]string
	FWDAddr, ListenAddr, FirewallType string
	WhitelistLo, WhiteListPrivate     []string
	WhitelistTTL                      int
}

// GetADHoleEnv will read environ and create a map of k:v from envs
// that have a NET_TRUST prefix. The prefix is removed
func GetNetTrustEnv() (*NetTrust, error) {
	fwdAddr := flag.String("fwd-addr", "", "NetTrust forward dns address")
	listenAddr := flag.String("listen-addr", "", "NetTrust listen dns address")
	firewallType := flag.String("firewall-type", "nftables", "NetTrust firewall type (nftables is only supported for now)")
	whitelistLoopback := flag.Bool("whitelist-loopback", true, "Loopback network space 127.0.0.0/8 will be whitelisted (default true)")
	whitelistPrivate := flag.Bool("whitelist-private", true, "If 10.0.0.0/8, 172.16.0.0/16, 192.168.0.0/16, 100.64.0.0/10 will be whitelisted")
	whitelistTTL := flag.Int("whitelist-ttl", -1, "Number of seconds a whitelisted host will be active before NetTrust expires it and expect a DNS query again (-1 do not expire)")
	flag.Parse()

	var key string
	env := make(map[string]string)
	osEnviron := os.Environ()
	NetTrustPrefix := "NET_TRUST_"
	for _, b := range osEnviron {
		if strings.HasPrefix(b, NetTrustPrefix) {
			pair := strings.SplitN(b, "=", 2)
			key = strings.TrimPrefix(pair[0], NetTrustPrefix)
			key = strings.ToLower(key)
			key = strings.Replace(key, "_", ".", -1)
			env[key] = pair[1]
		}
	}

	config := &NetTrust{}

	f, err := os.Stat("config.json")
	if !os.IsNotExist(err) && !f.IsDir() {
		body, err := ioutil.ReadFile("config.json")
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(body, config); err != nil {
			return nil, err
		}
	}

	config.Env = env
	config.FWDAddr = *fwdAddr
	config.ListenAddr = *listenAddr
	config.FirewallType = *firewallType
	config.WhitelistTTL = *whitelistTTL
	if *whitelistLoopback {
		config.WhitelistLo = []string{"127.0.0.0/8"}
	}
	if *whitelistPrivate {
		config.WhiteListPrivate = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}
	}

	return config, nil
}
