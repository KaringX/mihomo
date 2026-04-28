package dns

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver"

	D "github.com/miekg/dns"
)

const (
	SystemDnsFlushTime   = 5 * time.Minute
	SystemDnsDeleteTimes = 12 // 12*5 = 60min
)

type systemDnsClient struct {
	disableTimes uint32
	dnsClient
}

type systemClient struct {
	mu         sync.Mutex
	dnsClients map[string]*systemDnsClient
	lastFlush  time.Time
	defaultNS  []dnsClient
}

func (c *systemClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	dnsClients, _, err := c.getDnsClients() // meta-improve
	//if len(dnsClients) == 0 && len(c.defaultNS) > 0 {// meta-improve
	//	dnsClients = c.defaultNS
	//	err = nil
	//}
	if err != nil {
		return
	}
	msg, _, err = batchExchange(ctx, dnsClients, m)
	return
}

// Address implements dnsClient
func (c *systemClient) Address() string {
	dnsClients, isDefault, _ := c.getDnsClients() // meta-improve
	isDefaultStr := ""                            // meta-improve
	if isDefault {                                // meta-improve
		//dnsClients = c.defaultNS // meta-improve
		isDefaultStr = "[defaultNS]" // meta-improve
	}
	addrs := make([]string, 0, len(dnsClients))
	for _, c := range dnsClients {
		addrs = append(addrs, c.Address())
	}
	return fmt.Sprintf("system%s(%s)", isDefaultStr, strings.Join(addrs, ",")) // meta-improve
}

var _ dnsClient = (*systemClient)(nil)

func newSystemClient() *systemClient {
	return &systemClient{
		dnsClients: map[string]*systemDnsClient{},
	}
}

func init() {
	r := NewResolver(Config{})
	c := newSystemClient()
	c.defaultNS = transform([]NameServer{{Addr: "114.114.114.114:53"}, {Addr: "8.8.8.8:53"}, {Addr: "223.6.6.6:53"}}, nil) // meta-improve
	r.main = []dnsClient{c}
	resolver.SystemResolver = r
}
