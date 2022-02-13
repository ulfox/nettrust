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
	Env                       map[string]string
	DoNotFlushTable           bool   `json:"doNotFlushTable"`
	DoNotFlushAuthorizedHosts bool   `json:"doNotFlushAuthorizedHosts"`
	FWDAddr                   string `json:"fwdAddr"`
	FWDProto                  string `json:"fwdProto"`
	FWDTLS                    bool   `json:"fwdTLS"`
	FWDCaCert                 string `json:"fwdCaCert"`
	ListenAddr                string `json:"listenAddr"`
	FirewallType              string `json:"firewallType"`
	WhitelistLoEnabled        bool   `json:"whitelistLoEnabled"`
	WhitelistPrivateEnabled   bool   `json:"whitelistPrivateEnabled"`
	WhitelistLo               []string
	WhitelistPrivate          []string
	AuthorizedTTL             int `json:"ttl"`
	TTLCheckTicker            int `json:"ttlInterval"`
}

// GetADHoleEnv will read environ and create a map of k:v from envs
// that have a NET_TRUST prefix. The prefix is removed
func GetNetTrustEnv() (*NetTrust, error) {
	doNotFlushTable := flag.Bool(
		"do-not-flush-table",
		false,
		"Do not clean up tables when NetTrust exists. Use this flag if you want to continue to deny communication when NetTrust has exited",
	)
	doNotFlushAuthorizedHosts := flag.Bool(
		"do-not-flush-authorized-hosts",
		false,
		"Do not clean up the authorized hosts list on exit. Use this together with do-not-flush-table to keep the NetTrust table as is on exit",
	)
	fwdAddr := flag.String("fwd-addr", "", "NetTrust forward dns address")
	fwdProto := flag.String("fwd-proto", "", "NetTrust dns forward protocol")
	fwdTLS := flag.Bool(
		"fwd-tls",
		false,
		"Enable DoT. This expects that forward dns address supports DoT and fwd-proto is tcp",
	)
	fwdTLSCert := flag.String(
		"fwd-tls-cert",
		"",
		"path to certificate that will be used to validate forward dns hostname. If you do not set this, the the host root CAs will be used",
	)
	listenAddr := flag.String("listen-addr", "", "NetTrust listen dns address")
	firewallType := flag.String("firewall-type", "", "NetTrust firewall type (nftables is only supported for now)")
	whitelistLoopback := flag.Bool(
		"whitelist-loopback",
		true,
		"Loopback network space 127.0.0.0/8 will be whitelisted (default true)",
	)
	whitelistPrivate := flag.Bool(
		"whitelist-private",
		true,
		"If 10.0.0.0/8, 172.16.0.0/16, 192.168.0.0/16, 100.64.0.0/10 will be whitelisted (default true)",
	)
	authorizedTTL := flag.Int(
		"authorized-ttl",
		0,
		"Number of seconds a authorized host will be active before NetTrust expires it and expect a DNS query again (-1 do not expire)",
	)
	ttlCheckTicker := flag.Int(
		"ttl-check-ticker",
		0,
		"How often NetTrust should check the cache for expired authorized hosts (Checking is blocking, do not put small numbers)",
	)
	fileCFG := flag.String("config", "", "Path to config.json")
	flag.Parse()

	var key string
	var err error
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

	if *fileCFG != "" {
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
	}

	config.Env = env

	if *doNotFlushTable {
		config.DoNotFlushTable = *doNotFlushTable
	}

	if *doNotFlushAuthorizedHosts {
		config.DoNotFlushAuthorizedHosts = *doNotFlushAuthorizedHosts
	}

	if *fwdAddr != "" {
		config.FWDAddr = *fwdAddr
	}

	if *fwdProto == "" && config.FWDProto == "" {
		config.FWDProto = "udp"
	} else if *fwdProto != "" {
		config.FWDProto = *fwdProto
	}

	if *fwdTLS {
		config.FWDTLS = *fwdTLS
	}

	if *fwdTLSCert != "" {
		config.FWDCaCert = *fwdTLSCert
	}

	if config.FWDTLS && config.FWDCaCert != "" {
		err = fileExists(*fwdTLSCert)
		if err != nil {
			return nil, err
		}
	}

	if *listenAddr != "" {
		config.ListenAddr = *listenAddr
	}

	if config.ListenAddr == config.FWDAddr {
		return nil, fmt.Errorf(ErrSameAddr)
	}

	if *firewallType == "" && config.FirewallType == "" {
		config.FirewallType = "nftables"
	} else if *firewallType != "" {
		config.FirewallType = *firewallType
	}

	if *authorizedTTL == 0 && config.AuthorizedTTL == 0 {
		config.AuthorizedTTL = -1
	} else if *authorizedTTL != 0 {
		config.AuthorizedTTL = *authorizedTTL
	}

	if *ttlCheckTicker == 0 && config.TTLCheckTicker == 0 {
		config.TTLCheckTicker = 30
	} else if *ttlCheckTicker != 0 {
		config.TTLCheckTicker = *ttlCheckTicker
	}

	if *whitelistLoopback || config.WhitelistLoEnabled {
		config.WhitelistLo = []string{"127.0.0.0/8"}
	}

	if *whitelistPrivate || config.WhitelistPrivateEnabled {
		config.WhitelistPrivate = []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
		}
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
