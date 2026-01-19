// meta-improve
package common

import (
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/provider"
)

type NewGEOIPRulesetHookFunc func(country string, adapter string) (string, bool, error)

var (
	NewGEOIPRulesetHook NewGEOIPRulesetHookFunc
)

type GEOIPRuleset struct {
	*provider.RuleSet
	not bool
}

var _ C.Rule = (*GEOIPRuleset)(nil)

func (g *GEOIPRuleset) RuleType() C.RuleType {
	if g.RuleSet.Src() {
		return C.SrcGEOIP
	}
	return C.GEOIP
}

func (g *GEOIPRuleset) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if !g.NoResolveIP() && !g.Src() && helper.ResolveIP != nil {
		helper.ResolveIP()
	}

	ip := metadata.DstIP
	if g.Src() {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}
	match, adapter := g.RuleSet.Match(metadata, helper)
	if g.not {
		match = !match
	}
	return match, adapter
}

// MatchIp implements C.IpMatcher
func (g *GEOIPRuleset) MatchIp(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	match := g.RuleSet.MatchIp(ip)
	if g.not {
		match = !match
	}
	return match
}

// MatchIp implements C.IpMatcher
func (g dnsFallbackFilterRuleset) MatchIp(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if g.isLan(ip) { // compatible with original behavior
		return false
	}
	match := g.RuleSet.MatchIp(ip)
	if g.not {
		match = !match
	}
	return match
}

type dnsFallbackFilterRuleset struct {
	*GEOIPRuleset
}

func (g *GEOIPRuleset) DnsFallbackFilter() C.IpMatcher { // for dns.fallback-filter.geoip
	return dnsFallbackFilterRuleset{GEOIPRuleset: g}
}

func (g *GEOIPRuleset) isLan(ip netip.Addr) bool {
	return ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		resolver.IsFakeBroadcastIP(ip)
}

func (g *GEOIPRuleset) Adapter() string {
	return g.RuleSet.Adapter()
}

func (g *GEOIPRuleset) Payload() string {
	return g.RuleSet.Payload()
}

func (g *GEOIPRuleset) GetCountry() string {
	return g.Payload()
}

func (g *GEOIPRuleset) GetRecodeSize() int {
	return 0
}

func NewGEOIPRuleset(country string, adapter string, isSrc, noResolveIP bool) (*GEOIPRuleset, error) {
	country = strings.ToLower(country)
	country, not, err := NewGEOIPRulesetHook(country, adapter)
	if err != nil {
		return nil, err
	}
	ruleset, err := provider.NewRuleSet(country, adapter, isSrc, noResolveIP)
	if err != nil {
		return nil, err
	}
	return &GEOIPRuleset{
		RuleSet: ruleset,
		not:     not,
	}, nil
}
