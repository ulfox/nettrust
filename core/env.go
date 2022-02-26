package core

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
		Domains  []string `json:"domains"`
	} `json:"blacklist"`
	Env                       map[string]string
	DoNotFlushTable           bool   `json:"doNotFlushTable"`
	DoNotFlushAuthorizedHosts bool   `json:"doNotFlushAuthorizedHosts"`
	FWDAddr                   string `json:"fwdAddr"`
	FWDProto                  string `json:"fwdProto"`
	FWDTLS                    bool   `json:"fwdTLS"`
	FWDCaCert                 string `json:"fwdCaCert"`
	ListenAddr                string `json:"listenAddr"`
	ListenTLS                 bool   `json:"listenTLS"`
	ListenCert                string `json:"listenCert"`
	ListenCertKey             string `json:"listenCertKey"`
	FirewallType              string `json:"firewallType"`
	WhitelistLoEnabled        bool   `json:"whitelistLoEnabled"`
	WhitelistPrivateEnabled   bool   `json:"whitelistPrivateEnabled"`
	WhitelistLo               []string
	WhitelistPrivate          []string
	AuthorizedTTL             int `json:"ttl"`
	TTLCheckTicker            int `json:"ttlInterval"`
	DNSTTLCache               int `json:"dnsTTLCache"`
}

// GetNetTrustEnv will read environ and create a map of k:v from envs
// that have a NET_TRUST prefix. The prefix is removed
func GetNetTrustEnv() (*NetTrust, error) {
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

	if *listenTLS {
		config.ListenTLS = *listenTLS
	}

	if *listenCert != "" {
		config.ListenCert = *listenCert
	}

	if *listenCertKey != "" {
		config.ListenCertKey = *listenCertKey
	}

	if config.ListenTLS {
		if config.ListenCert == "" {
			return nil, fmt.Errorf(errListenTLSNoFile, "certificate")
		}
		if config.ListenCertKey == "" {
			return nil, fmt.Errorf(errListenTLSNoFile, "private key")
		}
		err = fileExists(config.ListenCert)
		if err != nil {
			return nil, err
		}
		err = fileExists(config.ListenCertKey)
		if err != nil {
			return nil, err
		}
	}

	if config.ListenAddr == config.FWDAddr {
		return nil, fmt.Errorf(errSameAddr)
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

	if *dnsTTLCache == 0 && config.DNSTTLCache == 0 {
		config.DNSTTLCache = -1
	} else if *dnsTTLCache != 0 {
		config.DNSTTLCache = *dnsTTLCache
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
