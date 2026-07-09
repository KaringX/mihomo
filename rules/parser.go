package rules

import (
	"fmt"
	"runtime"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	RG "github.com/metacubex/mihomo/rules/geo_asn_ruleset"
	"github.com/metacubex/mihomo/rules/logic"
	RP "github.com/metacubex/mihomo/rules/provider"
)

func ParseRule(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, ignore bool, parseErr error) { // meta-improve
	if tp != "MATCH" && payload == "" { // only MATCH allowed doesn't contain payload
		return nil, false, fmt.Errorf("missing subsequent parameters: %s", tp) // meta-improve
	}
	ignore = false // meta-improve
	switch tp {
	case "DOMAIN":
		parsed = RC.NewDomain(payload, target)
	case "DOMAIN-SUFFIX":
		parsed = RC.NewDomainSuffix(payload, target)
	case "DOMAIN-KEYWORD":
		parsed = RC.NewDomainKeyword(payload, target)
	case "DOMAIN-REGEX":
		parsed, parseErr = RC.NewDomainRegex(payload, target)
	case "DOMAIN-WILDCARD":
		parsed, parseErr = RC.NewDomainWildcard(payload, target)
	case "GEOSITE":
		parsed, parseErr = RG.NewGEOSITERuleset(payload, target) //meta-improve
	case "GEOIP":
		isSrc, noResolve := RC.ParseParams(params)
		if strings.ToLower(payload) == "lan" { //meta-improve
			parsed, parseErr = RG.NewGEOIPLan(payload, target, isSrc, noResolve) //meta-improve
		} else {
			parsed, parseErr = RG.NewGEOIPRuleset(payload, target, isSrc, noResolve) //meta-improve
		}
	case "SRC-GEOIP":
		if strings.ToLower(payload) == "lan" { //meta-improve
			parsed, parseErr = RG.NewGEOIPLan(payload, target, true, true) //meta-improve
		} else {
			parsed, parseErr = RG.NewGEOIPRuleset(payload, target, true, true) //meta-improve
		}
	case "IP-ASN":
		ignore = runtime.GOOS == "ios" // meta-improve
		if !ignore {                   // meta-improve
			isSrc, noResolve := RC.ParseParams(params)
			parsed, parseErr = RC.NewIPASN(payload, target, isSrc, noResolve)
			//parsed, parseErr = RG.NewIPASNRuleset(payload, target, isSrc, noResolve) //meta-improve
		}
	case "SRC-IP-ASN":
		ignore = runtime.GOOS == "ios" // meta-improve
		if !ignore {                   // meta-improve
			parsed, parseErr = RC.NewIPASN(payload, target, true, true)
			//parsed, parseErr = RG.NewIPASNRuleset(payload, target, true, true) //meta-improve
		}
	case "IP-CIDR", "IP-CIDR6":
		isSrc, noResolve := RC.ParseParams(params)
		parsed, parseErr = RC.NewIPCIDR(payload, target, RC.WithIPCIDRSourceIP(isSrc), RC.WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = RC.NewIPCIDR(payload, target, RC.WithIPCIDRSourceIP(true), RC.WithIPCIDRNoResolve(true))
	case "IP-SUFFIX":
		isSrc, noResolve := RC.ParseParams(params)
		parsed, parseErr = RC.NewIPSuffix(payload, target, isSrc, noResolve)
	case "SRC-IP-SUFFIX":
		parsed, parseErr = RC.NewIPSuffix(payload, target, true, true)
	case "SRC-PORT":
		parsed, parseErr = RC.NewPort(payload, target, C.SrcPort)
	case "DST-PORT":
		parsed, parseErr = RC.NewPort(payload, target, C.DstPort)
	case "IN-PORT":
		parsed, parseErr = RC.NewPort(payload, target, C.InPort)
	case "DSCP":
		parsed, parseErr = RC.NewDSCP(payload, target)
	case "PROCESS-NAME":
		parsed, parseErr = RC.NewProcess(payload, target, C.ProcessName)
	case "PROCESS-PATH":
		parsed, parseErr = RC.NewProcess(payload, target, C.ProcessPath)
	case "PROCESS-NAME-REGEX":
		parsed, parseErr = RC.NewProcess(payload, target, C.ProcessNameRegex)
	case "PROCESS-PATH-REGEX":
		parsed, parseErr = RC.NewProcess(payload, target, C.ProcessPathRegex)
	case "PROCESS-NAME-WILDCARD":
		parsed, parseErr = RC.NewProcess(payload, target, C.ProcessNameWildcard)
	case "PROCESS-PATH-WILDCARD":
		parsed, parseErr = RC.NewProcess(payload, target, C.ProcessPathWildcard)
	case "NETWORK":
		parsed, parseErr = RC.NewNetworkType(payload, target)
	case "UID":
		parsed, parseErr = RC.NewUid(payload, target)
	case "IN-TYPE":
		parsed, parseErr = RC.NewInType(payload, target)
	case "IN-USER":
		parsed, parseErr = RC.NewInUser(payload, target)
	case "IN-NAME":
		parsed, parseErr = RC.NewInName(payload, target)
	case "REMATCH-NAME":
		parsed, parseErr = RC.NewRematchName(payload, target)
	case "SUB-RULE":
		parsed, parseErr = logic.NewSubRule(payload, target, subRules, ParseRule)
	case "AND":
		parsed, parseErr = logic.NewAND(payload, target, ParseRule)
	case "OR":
		parsed, parseErr = logic.NewOR(payload, target, ParseRule)
	case "NOT":
		parsed, parseErr = logic.NewNOT(payload, target, ParseRule)
	case "RULE-SET":
		isSrc, noResolve := RC.ParseParams(params)
		parsed, parseErr = RP.NewRuleSet(payload, target, isSrc, noResolve)
	case "MATCH":
		parsed = RC.NewMatch(target)
		parseErr = nil
	default:
		parseErr = fmt.Errorf("unsupported rule type: %s", tp)
	}

	if parseErr != nil {
		return nil, ignore, parseErr //meta-improve
	}

	return
}

var _ RC.ParseRuleFunc = ParseRule
