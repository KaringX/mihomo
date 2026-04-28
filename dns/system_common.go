//go:build !(android && cmfa)

package dns

import (
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	"golang.org/x/exp/slices"
)

func (c *systemClient) getDnsClients() ([]dnsClient, bool, error) { // meta-improve
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	if time.Since(c.lastFlush) > SystemDnsFlushTime {
		var nameservers []string
		if nameservers, err = dnsReadConfig(); err == nil && len(nameservers) > 0 { // meta-improve
			log.Debugln("[DNS] system dns update to %s", nameservers)
			for _, addr := range nameservers {
				if resolver.IsSystemDnsBlacklisted(addr) {
					continue
				}
				if _, ok := c.dnsClients[addr]; !ok {
					clients := transform(
						[]NameServer{{
							Addr: net.JoinHostPort(addr, "53"),
							Net:  "udp",
						}},
						nil,
					)
					if len(clients) > 0 {
						c.dnsClients[addr] = &systemDnsClient{
							disableTimes: 0,
							dnsClient:    clients[0],
						}
					}
				}
			}
			available := 0
			for nameserver, sdc := range c.dnsClients {
				if slices.Contains(nameservers, nameserver) {
					sdc.disableTimes = 0 // enable
					available++
				} else {
					if sdc.disableTimes > SystemDnsDeleteTimes {
						delete(c.dnsClients, nameserver) // drop too old dnsClient
					} else {
						sdc.disableTimes++
					}
				}
			}
			if available > 0 {
				c.lastFlush = time.Now()
			}
		} else { // meta-improve
			c.lastFlush = time.Now().Add(SystemDnsFlushTime / 2)
		}
	}
	dnsClients := make([]dnsClient, 0, len(c.dnsClients))
	for _, sdc := range c.dnsClients {
		if sdc.disableTimes == 0 {
			dnsClients = append(dnsClients, sdc.dnsClient)
		}
	}
	if len(dnsClients) == 0 && len(c.defaultNS) > 0 { // meta-improve
		addrs := make([]string, 0, len(c.defaultNS))
		for _, c := range c.defaultNS {
			addrs = append(addrs, c.Address())
		}
		log.Debugln("[DNS] system dns downgrade to defaultNS: %s", strings.Join(addrs, ","))
		dnsClients = c.defaultNS
		return dnsClients, true, nil
	}
	if len(dnsClients) > 0 {
		return dnsClients, false, nil // meta-improve
	}
	return nil, false, err // meta-improve
}

func (c *systemClient) ResetConnection() {}
