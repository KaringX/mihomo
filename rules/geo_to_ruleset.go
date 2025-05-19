package rules

import (
	"fmt"
	"strings"

	providerTypes "github.com/metacubex/mihomo/constant/provider"

	RP "github.com/metacubex/mihomo/rules/provider"
)

var (
	geositeRulesetUrl string
	geoipRulesetUrl   string
	asnRulesetUrl     string
	updateInterval    int
	downloadProxy     string
)

func SetDownloadProxy(proxy string) {
	downloadProxy = proxy
}

func GetDownloadProxy() string {
	return downloadProxy
}

func SetUpdateInterval(interval int) {
	updateInterval = interval
}

func GetUpdateInterval() int {
	return updateInterval
}

func SetGeositeRuleSetUrl(url string) {
	geositeRulesetUrl = url
}

func GetGeositeRuleSetUrl() string {
	return geositeRulesetUrl
}

func SetGeoipRuleSetUrl(url string) {
	geoipRulesetUrl = url
}

func GetGeoipRuleSetUrl() string {
	return geoipRulesetUrl
}

func SetAsnRuleSetUrl(url string) {
	asnRulesetUrl = url
}

func GetAsnRuleSetUrl() string {
	return asnRulesetUrl
}

func NewRuleSetGeositeName(name string) string {
	return fmt.Sprintf("geosite-ruleset-%s", strings.ToLower(name))
}

func NewRuleSetGeoipName(name string) string {
	return fmt.Sprintf("geoip-ruleset-%s", strings.ToLower(name))
}

func NewRuleSetAsnName(name string) string {
	return fmt.Sprintf("asn-ruleset-%s", strings.ToLower(name))
}

func AddRuleSetGeosite(rulesetName string, ruleProviders map[string]providerTypes.RuleProvider) (string, error) {
	rulesetName = strings.ToLower(rulesetName)
	rulesetNameNew := NewRuleSetGeositeName(rulesetName)
	if _, ok := ruleProviders[rulesetNameNew]; !ok {
		mapping := make(map[string]any)
		mapping["origin_ruleset"] = rulesetName
		mapping["origin_ruleset_type"] = "geosite"
		mapping["type"] = "http"
		mapping["behavior"] = "domain"
		mapping["format"] = "mrs"
		mapping["path"] = fmt.Sprintf("./ruleset/geosite/%s.mrs", rulesetName)
		mapping["url"] = fmt.Sprintf("%s/%s.mrs", GetGeositeRuleSetUrl(), rulesetName)
		mapping["interval"] = updateInterval
		mapping["proxy"] = GetDownloadProxy()
		rp, err := RP.ParseRuleProvider(rulesetNameNew, mapping, ParseRule)
		if err != nil {
			return "", err
		}

		ruleProviders[rulesetNameNew] = rp
	}
	return rulesetNameNew, nil
}

func AddRuleSetGeosite2(rulesetName string, ruleProviders map[string]map[string]any) {
	rulesetName = strings.ToLower(rulesetName)
	rulesetNameNew := NewRuleSetGeositeName(rulesetName)
	if _, ok := ruleProviders[rulesetNameNew]; !ok {
		mapping := make(map[string]any)
		mapping["origin_ruleset"] = rulesetName
		mapping["origin_ruleset_type"] = "geosite"
		mapping["type"] = "http"
		mapping["behavior"] = "domain"
		mapping["format"] = "mrs"
		mapping["path"] = fmt.Sprintf("./ruleset/geosite/%s.mrs", rulesetName)
		mapping["url"] = fmt.Sprintf("%s/%s.mrs", GetGeositeRuleSetUrl(), rulesetName)
		mapping["interval"] = GetUpdateInterval()
		mapping["proxy"] = GetDownloadProxy()
		ruleProviders[rulesetNameNew] = mapping
	}
}

func AddRuleSetGeoip(rulesetName string, ruleProviders map[string]providerTypes.RuleProvider) (string, error) {
	rulesetName = strings.ToLower(rulesetName)
	rulesetNameNew := NewRuleSetGeoipName(rulesetName)
	if _, ok := ruleProviders[rulesetNameNew]; !ok {
		mapping := make(map[string]any)
		mapping["origin_ruleset"] = rulesetName
		mapping["origin_ruleset_type"] = "geoip"
		mapping["type"] = "http"
		mapping["behavior"] = "ipcidr"
		mapping["format"] = "mrs"
		mapping["path"] = fmt.Sprintf("./ruleset/geoip/%s.mrs", rulesetName)
		mapping["url"] = fmt.Sprintf("%s/%s.mrs", GetGeoipRuleSetUrl(), rulesetName)
		mapping["interval"] = updateInterval
		mapping["proxy"] = GetDownloadProxy()
		rp, err := RP.ParseRuleProvider(rulesetNameNew, mapping, ParseRule)
		if err != nil {
			return "", err
		}

		ruleProviders[rulesetNameNew] = rp

	}
	return rulesetNameNew, nil
}

func AddRuleSetGeoip2(rulesetName string, ruleProviders map[string]map[string]any) {
	rulesetName = strings.ToLower(rulesetName)
	rulesetNameNew := NewRuleSetGeoipName(rulesetName)
	if _, ok := ruleProviders[rulesetNameNew]; !ok {
		mapping := make(map[string]any)
		mapping["origin_ruleset"] = rulesetName
		mapping["origin_ruleset_type"] = "geoip"
		mapping["type"] = "http"
		mapping["behavior"] = "ipcidr"
		mapping["format"] = "mrs"
		mapping["path"] = fmt.Sprintf("./ruleset/geoip/%s.mrs", rulesetName)
		mapping["url"] = fmt.Sprintf("%s/%s.mrs", GetGeoipRuleSetUrl(), rulesetName)
		mapping["interval"] = GetUpdateInterval()
		mapping["proxy"] = GetDownloadProxy()
		ruleProviders[rulesetNameNew] = mapping
	}
}

func AddRuleSetAsn2(rulesetName string, ruleProviders map[string]map[string]any) {
	rulesetName = strings.ToLower(rulesetName)
	rulesetNameNew := NewRuleSetAsnName(rulesetName)
	if _, ok := ruleProviders[rulesetNameNew]; !ok {
		mapping := make(map[string]any)
		mapping["origin_ruleset"] = rulesetName
		mapping["origin_ruleset_type"] = "asn"
		mapping["type"] = "http"
		mapping["behavior"] = "ipcidr"
		mapping["format"] = "mrs"
		mapping["path"] = fmt.Sprintf("./ruleset/asn/%s.mrs", rulesetName)
		mapping["url"] = fmt.Sprintf("%s/%s.mrs", GetAsnRuleSetUrl(), rulesetName)
		mapping["interval"] = GetUpdateInterval()
		mapping["proxy"] = GetDownloadProxy()
		ruleProviders[rulesetNameNew] = mapping
	}
}
