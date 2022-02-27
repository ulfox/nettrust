package main

import (
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/ulfox/nettrust/authorizer"
	"github.com/ulfox/nettrust/dns"
	"github.com/ulfox/nettrust/firewall"

	"github.com/ulfox/nettrust/core"
)

const (
	tableNameOutput = "net-trust"
	chainNameOutput = "authorized-output"
	authorizedSet   = "authorized"
	chainNameInput  = "input"
)

var (
	logger *logrus.Logger
)

func main() {

	logger = logrus.New()
	logger.SetFormatter(
		&logrus.TextFormatter{FullTimestamp: true},
	)

	log := logger.WithFields(logrus.Fields{
		"Component": "NetTrust",
		"Stage":     "main",
	})

	// Read Nettrust environment and config
	config, err := core.GetNetTrustEnv()
	if err != nil {
		log.Fatal(err)
	}
	// Does nothing for now. Check ToDo.md, debug logs will be added in the future
	if config.Env["debug"] == "true" {
		logger.SetLevel(logrus.DebugLevel)
	}

	if !config.DoNotFlushTable {
		log.Warn(core.WarnOnExitFlush)
	}

	if config.DoNotFlushAuthorizedHosts {
		log.Warn("on exit NetTrust will not flush the authorized hosts list")
	}

	// DNS Server
	dnsServer, err := dns.NewDNSServer(
		config.ListenAddr,
		config.FWDAddr,
		config.FWDProto,
		config.ListenCert,
		config.ListenCertKey,
		config.FWDCaCert,
		config.ListenTLS,
		config.FWDTLS,
		config.DNSTTLCache,
		config.Blacklist.Domains,
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Firewall
	fw, err := firewall.NewFirewall(
		config.FirewallBackend,
		config.FirewallType,
		tableNameOutput,
		chainNameOutput,
		config.FirewallDropInput,
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create default chains, tables and rules
	// This also applies any whitelist that may have been provided
	err = makeDefaultRules(fw, config)
	if err != nil {
		log.Fatal(err)
	}

	for k, v := range config.Env {
		if strings.HasPrefix(k, "blacklist.networks") {
			err = core.CheckIPV4Network(v)
			if err != nil {
				log.Fatal(err)
			}
			config.Blacklist.Networks = append(config.Blacklist.Networks, v)
		}
	}

	for k, v := range config.Env {
		if strings.HasPrefix(k, "blacklist.hosts") {
			err = core.CheckIPV4Addresses(v)
			if err != nil {
				log.Fatal(err)
			}
			config.Blacklist.Hosts = append(config.Blacklist.Hosts, v)
		}
	}

	authorizer, cacheContext, err := authorizer.NewAuthorizer(
		config.AuthorizedTTL,
		config.TTLCheckTicker,
		authorizedSet,
		config.Blacklist.Hosts,
		config.Blacklist.Networks,
		config.DoNotFlushAuthorizedHosts,
		fw,
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Init DNS Servers
	udpDNSServerContext := dnsServer.UDPListenBackground(
		authorizer.HandleRequest)
	tcpDNSServerContext := dnsServer.TCPListenBackground(
		authorizer.HandleRequest)

	sysSigs := core.NewOSSignal()

	sysSigs.Wait()
	log.Infof("Interrupted")

	udpDNSServerContext.Expire()
	tcpDNSServerContext.Expire()

	udpDNSServerContext.Wait()
	tcpDNSServerContext.Wait()

	cacheContext.Expire()
	cacheContext.Wait()

	if !config.DoNotFlushTable {
		log.Info("flush table is enabled, flushing ...")
		err = fw.FlushTable(tableNameOutput)
		if err != nil {
			log.Fatal(err)
		}

		err = fw.DeleteChain(chainNameOutput)
		if err != nil {
			log.Fatal(err)
		}
		if config.FirewallDropInput {
			err = fw.DeleteChain(chainNameInput)
			if err != nil {
				log.Fatal(err)
			}
		}
		err = fw.DeleteTable(tableNameOutput)
		if err != nil {
			log.Fatal(err)
		}
	}

}

func makeDefaultRules(fw *firewall.Firewall, config *core.NetTrust) error {
	var err error

	for _, v := range config.WhitelistLo {
		err = core.CheckIPV4Network(v)
		if err != nil {
			return err
		}

		err = fw.AddIPv4NetworkRule(v)
		if err != nil {
			return err
		}
	}

	for _, v := range config.WhitelistPrivate {
		err = core.CheckIPV4Network(v)
		if err != nil {
			return err
		}

		err = fw.AddIPv4NetworkRule(v)
		if err != nil {
			return err
		}
	}

	for k, v := range config.Env {
		if strings.HasPrefix(k, "whitelist.networks") {
			err = core.CheckIPV4Network(v)
			if err != nil {
				return err
			}

			err = fw.AddIPv4NetworkRule(v)
			if err != nil {
				return err
			}
		}
	}

	for _, v := range config.Whitelist.Networks {
		err = core.CheckIPV4Network(v)
		if err != nil {
			return err
		}

		err = fw.AddIPv4NetworkRule(v)
		if err != nil {
			return err
		}
	}

	err = fw.AddIPv4Set("whitelist")
	if err != nil {
		return err
	}

	err = fw.AddIPv4SetRule("whitelist")
	if err != nil {
		return err
	}

	for _, n := range []string{config.ListenAddr, config.FWDAddr} {
		err = core.CheckIPV4SocketAddress(n)
		if err != nil {
			return err
		}

		err = fw.AddIPv4ToSetRule("whitelist", strings.Split(n, ":")[0])
		if err != nil {
			return err
		}
	}

	for k, v := range config.Env {
		if strings.HasPrefix(k, "whitelist.hosts") {
			err = core.CheckIPV4Addresses(v)
			if err != nil {
				return err
			}

			err = fw.AddIPv4ToSetRule("whitelist", v)
			if err != nil {
				return err
			}
		}
	}

	for _, v := range config.Whitelist.Hosts {
		err = core.CheckIPV4Addresses(v)
		if err != nil {
			return err
		}

		err = fw.AddIPv4ToSetRule("whitelist", v)
		if err != nil {
			return err
		}
	}

	err = fw.AddIPv4Set(authorizedSet)
	if err != nil {
		return err
	}

	err = fw.AddIPv4SetRule(authorizedSet)
	if err != nil {
		return err
	}

	err = fw.AddTailingReject()
	if err != nil {
		return err
	}

	return nil
}
