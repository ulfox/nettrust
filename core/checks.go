package core

import (
	"fmt"
	"strconv"
	"strings"
)

func emptyStringE(s string) error {
	if s == "" {
		return fmt.Errorf("is empty")
	}

	return nil
}

// CheckIPV4SocketAddress checks if input strings can be split into ip/port pairs
func CheckIPV4SocketAddress(address string) error {
	strSlice := strings.Split(address, ":")
	if len(strSlice) != 2 {
		return fmt.Errorf(errInvalidSocketAddress, address)
	}

	if es := emptyStringE(strSlice[0]); es != nil {
		return fmt.Errorf("IP [%s] %s", address, es)
	}
	if es := emptyStringE(strSlice[1]); es != nil {
		return fmt.Errorf("port [%s] %s", address, es)
	}

	port, err := strconv.Atoi(strSlice[1])
	if err != nil {
		return err
	}

	if port < 1 || port > 65535 {
		return fmt.Errorf(errInvalidPort, port)
	}

	if err := CheckIPV4Addresses(strSlice[0]); err != nil {
		return err
	}

	return nil
}

// CheckIPV4Addresses simple method for checking if an address is a correct
// ipv4 address
func CheckIPV4Addresses(addr string) error {
	ipSlice := strings.Split(addr, ".")

	for _, oct := range ipSlice {
		octInt, err := strconv.Atoi(oct)
		if err != nil {
			return err
		}
		if octInt < 0 || octInt > 255 {
			return fmt.Errorf(errNotValidIPv4Addr, addr)
		}
	}

	return nil
}

// CheckIPV4Network simple method for checking if a network is a correct
// ipv4 network
func CheckIPV4Network(addr string) error {
	netSlice := strings.Split(addr, "/")
	err := CheckIPV4Addresses(netSlice[0])
	if err != nil {
		return err
	}

	cidr, err := strconv.Atoi(netSlice[1])
	if err != nil {
		return err
	}

	if cidr < 0 || cidr > 32 {
		return fmt.Errorf(errNotValidIPv4Network, addr)
	}

	return nil
}
