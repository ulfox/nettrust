package utils

import (
	"encoding/json"
	"flag"
	"fmt"
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
	Env                                                    map[string]string
	FWDAddr, ListenAddr, FirewallType, FWDProto, FWDCaCert string
	WhitelistLo, WhiteListPrivate                          []string
	AuthorizedTTL, TTLCheckTicker                          int
	FWDTLS                                                 bool
}

// GetADHoleEnv will read environ and create a map of k:v from envs
// that have a NET_TRUST prefix. The prefix is removed
func GetNetTrustEnv() (*NetTrust, error) {
	fwdAddr := flag.String("fwd-addr", "", "NetTrust forward dns address")
	fwdProto := flag.String("fwd-proto", "udp", "NetTrust dns forward protocol")
	fwdTLS := flag.Bool("fwd-tls", false, "Enable DoT. This expects that forward dns address supports DoT and fwd-proto is tcp")
	fwdTLSCert := flag.String("fwd-tls-cert", "", "path to certificate that will be used to validate forward dns hostname")
	listenAddr := flag.String("listen-addr", "", "NetTrust listen dns address")
	firewallType := flag.String("firewall-type", "nftables", "NetTrust firewall type (nftables is only supported for now)")
	whitelistLoopback := flag.Bool("whitelist-loopback", true, "Loopback network space 127.0.0.0/8 will be whitelisted (default true)")
	whitelistPrivate := flag.Bool("whitelist-private", true, "If 10.0.0.0/8, 172.16.0.0/16, 192.168.0.0/16, 100.64.0.0/10 will be whitelisted")
	authorizedTTL := flag.Int("authorized-ttl", -1, "Number of seconds a authorized host will be active before NetTrust expires it and expect a DNS query again (-1 do not expire)")
	ttlCheckTicker := flag.Int("ttl-check-ticker", 30, "How often NetTrust should check the cache for expired authorized hosts (Checking is blocking, do not put small numbers)")
	fileCFG := flag.String("config", "config.json", "Path to config.json")
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

	err := fileExists(*fileCFG)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadFile(*fileCFG)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, config); err != nil {
		return nil, err
	}

	if *fwdTLS && *fwdTLSCert != "" {
		err = fileExists(*fwdTLSCert)
		if err != nil {
			return nil, err
		}
	}

	config.Env = env
	config.FWDAddr = *fwdAddr
	config.ListenAddr = *listenAddr
	config.FirewallType = *firewallType
	config.AuthorizedTTL = *authorizedTTL
	config.FWDProto = *fwdProto
	config.TTLCheckTicker = *ttlCheckTicker
	config.FWDTLS = *fwdTLS
	config.FWDCaCert = *fwdTLSCert
	if *whitelistLoopback {
		config.WhitelistLo = []string{"127.0.0.0/8"}
	}
	if *whitelistPrivate {
		config.WhiteListPrivate = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}
	}

	return config, nil
}

func fileExists(file string) error {
	f, err := os.Stat(file)
	if os.IsNotExist(err) {
		return err
	}

	if f.IsDir() {
		return fmt.Errorf("[%s] is a directory", file)
	}

	return nil
}
