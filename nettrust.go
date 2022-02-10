package main

import (
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/ulfox/nettrust/dns"
	"github.com/ulfox/nettrust/firewall"

	"github.com/ulfox/nettrust/utils"
)

const (
	tableName     = "net-trust"
	chainName     = "authorized-output"
	authorizedSet = "authorized"
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
		"Stage":     "Initializing",
	})

	// Read Nettrust environment and config
	config, err := utils.GetNetTrustEnv()
	if err != nil {
		log.Fatal(err)
	}
	// Does nothing for now. Check ToDo.md, debug logs will be added in the future
	if config.Env["debug"] == "true" {
		logger.SetLevel(logrus.DebugLevel)
	}

	// DNS Server
	dnsServer, err := dns.NewDNSServer(
		config.ListenAddr,
		config.FWDAddr,
		config.WhitelistTTL,
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Firewall
	fw, fwContext, err := dnsServer.FirewallStart(
		config.FirewallType,
		tableName,
		chainName,
		authorizedSet,
		config.Blacklist.Hosts,
		config.Blacklist.Networks,
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

	// Init DNS Servers
	udpDNSServerContext := dnsServer.UDPListenBackground()
	tcpDNSServerContext := dnsServer.TCPListenBackground()

	sysSigs := utils.NewOSSignal()

	sysSigs.Wait()
	log.Infof("Interrupted")

	udpDNSServerContext.Expire()
	tcpDNSServerContext.Expire()

	udpDNSServerContext.Wait()
	tcpDNSServerContext.Wait()

	fwContext.Expire()
	fwContext.Wait()
}

func makeDefaultRules(fw *firewall.Firewall, config *utils.NetTrust) error {
	var err error

	for _, v := range config.WhitelistLo {
		err = utils.CheckIPV4Network(v)
		if err != nil {
			return err
		}

		err = fw.AddIPv4NetworkRule(v)
		if err != nil {
			return err
		}
	}

	for _, v := range config.WhiteListPrivate {
		err = utils.CheckIPV4Network(v)
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
			err = utils.CheckIPV4Network(v)
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
		err = utils.CheckIPV4Network(v)
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
		err = utils.CheckIPV4SocketAddress(n)
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
			err = utils.CheckIPV4Addresses(v)
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
		err = utils.CheckIPV4Addresses(v)
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

	err = fw.AddRejectVerdict()
	if err != nil {
		return err
	}

	return nil
}
