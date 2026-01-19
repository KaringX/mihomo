// meta-improve
package common

import (
	"strings"

	_ "github.com/metacubex/mihomo/component/geodata/memconservative"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/provider"
)

type NewGEOSITERulesetHookFunc func(country string, adapter string) (string, bool, error)

var (
	NewGEOSITERulesetHook NewGEOSITERulesetHookFunc
)

type GEOSITERuleset struct {
	*provider.RuleSet
	not bool
}

var _ C.Rule = (*GEOSITERuleset)(nil)

func (gs *GEOSITERuleset) RuleType() C.RuleType {
	return C.GEOSITE
}

func (gs *GEOSITERuleset) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	return gs.MatchDomain(metadata.RuleHost()), gs.Adapter()
}

// MatchDomain implements C.DomainMatcher
func (gs *GEOSITERuleset) MatchDomain(domain string) bool {
	match := gs.RuleSet.MatchDomain(domain)
	if gs.not {
		match = !match
	}
	return match
}

func (gs *GEOSITERuleset) Adapter() string {
	return gs.RuleSet.Adapter()
}

func (gs *GEOSITERuleset) Payload() string {
	return gs.RuleSet.Payload()
}

func (g *GEOSITERuleset) GetCountry() string {
	return g.Payload()
}

func (gs *GEOSITERuleset) GetRecodeSize() int {
	return 0
}

func NewGEOSITERuleset(country string, adapter string) (*GEOSITERuleset, error) {
	country = strings.ToLower(country)
	country, not, err := NewGEOSITERulesetHook(country, adapter)
	if err != nil {
		return nil, err
	}
	ruleset, err := provider.NewRuleSet(country, adapter, false, false)
	if err != nil {
		return nil, err
	}
	return &GEOSITERuleset{
		RuleSet: ruleset,
		not:     not,
	}, nil
}
