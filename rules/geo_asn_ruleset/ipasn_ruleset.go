// meta-improve
package common

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/provider"
)

type NewASNRulesetHookFunc func(asn string, adapter string) (string, error)

var (
	NewASNRulesetHook NewASNRulesetHookFunc
)

type ASNRuleset struct {
	*provider.RuleSet
}

var _ C.Rule = (*ASNRuleset)(nil)

func (a *ASNRuleset) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	return a.RuleSet.Match(metadata, helper)
}

func (a *ASNRuleset) RuleType() C.RuleType {
	if a.RuleSet.Src() {
		return C.SrcIPASN
	}
	return C.IPASN
}

func (a *ASNRuleset) Adapter() string {
	return a.RuleSet.Adapter()
}

func (a *ASNRuleset) Payload() string {
	return a.RuleSet.Payload()
}

func (a *ASNRuleset) GetASN() string {
	return a.Payload()
}

func NewIPASNRuleset(asn string, adapter string, isSrc, noResolveIP bool) (*ASNRuleset, error) {
	asn = strings.ToUpper(asn)
	asn, err := NewASNRulesetHook(asn, adapter)
	if err != nil {
		return nil, err
	}
	ruleset, err := provider.NewRuleSet(asn, adapter, isSrc, noResolveIP)
	if err != nil {
		return nil, err
	}
	return &ASNRuleset{
		RuleSet: ruleset,
	}, nil
}
