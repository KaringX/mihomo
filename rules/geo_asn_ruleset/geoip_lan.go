// meta-improve
package common

import (
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/common"
)

type NewGEOIPLanHookFunc func(country string, adapter string) (string, error)

var (
	NewGEOIPLanHook NewGEOIPLanHookFunc
)

type GEOIPLan struct {
	*common.Base
	ruleProviderName string
	adapter          string
	isSrc            bool
	noResolveIP      bool
}

var _ C.Rule = (*GEOIPLan)(nil)

func (g *GEOIPLan) RuleType() C.RuleType {
	if g.isSrc {
		return C.SrcGEOIP
	}
	return C.GEOIP
}

func (g *GEOIPLan) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if !g.noResolveIP && !g.isSrc && helper.ResolveIP != nil {
		helper.ResolveIP()
	}

	ip := metadata.DstIP
	if g.isSrc {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}

	return g.isLan(ip), g.Adapter()
}

// MatchIp implements C.IpMatcher
func (g *GEOIPLan) MatchIp(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	return g.isLan(ip)
}

// MatchIp implements C.IpMatcher
func (g dnsFallbackFilterLan) MatchIp(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if g.isLan(ip) { // compatible with original behavior
		return false
	}
	return false
}

type dnsFallbackFilterLan struct {
	*GEOIPLan
}

func (g *GEOIPLan) DnsFallbackFilter() C.IpMatcher { // for dns.fallback-filter.geoip
	return dnsFallbackFilterLan{GEOIPLan: g}
}

func (g *GEOIPLan) isLan(ip netip.Addr) bool {
	return ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		resolver.IsFakeBroadcastIP(ip)
}

func (g *GEOIPLan) Adapter() string {
	return g.adapter
}

func (g *GEOIPLan) Payload() string {
	return g.ruleProviderName
}

func (g *GEOIPLan) GetCountry() string {
	return g.Payload()
}

func (g *GEOIPLan) GetRecodeSize() int {
	return 0
}

func NewGEOIPLan(country string, adapter string, isSrc, noResolveIP bool) (*GEOIPLan, error) {
	country = strings.ToLower(country)
	country, err := NewGEOIPLanHook(country, adapter)
	if err != nil {
		return nil, err
	}

	return &GEOIPLan{
		Base:             &common.Base{},
		ruleProviderName: country,
		adapter:          adapter,
		isSrc:            isSrc,
		noResolveIP:      noResolveIP,
	}, nil
}
