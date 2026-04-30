package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Policy struct {
	IPGroups             map[string][]string   `json:"ip_groups"`
	DNSServers           []string              `json:"dns_servers"`
	RuleCollectionGroups []RuleCollectionGroup `json:"rule_collection_groups"`
}

type RuleCollectionGroup struct {
	Name                   string                  `json:"name"`
	Priority               int                     `json:"priority"`
	NetworkRuleCollections []NetworkRuleCollection `json:"network_rule_collections"`
	AppRuleCollections     []AppRuleCollection     `json:"app_rule_collections"`
}

type NetworkRuleCollection struct {
	Name     string        `json:"name"`
	Priority int           `json:"priority"`
	Action   string        `json:"action"`
	Rules    []NetworkRule `json:"rules"`
}

type AppRuleCollection struct {
	Name     string    `json:"name"`
	Priority int       `json:"priority"`
	Action   string    `json:"action"`
	Rules    []AppRule `json:"rules"`
}

type NetworkRule struct {
	Name          string   `json:"name"`
	Priority      int      `json:"priority"`
	Source        []string `json:"source"`
	Destination   []string `json:"destination"`
	Ports         []string `json:"ports"`
	Protocol      string   `json:"protocol"`
	Justification string   `json:"justification"`
}

type AppRule struct {
	Name          string   `json:"name"`
	Priority      int      `json:"priority"`
	Source        []string `json:"source"`
	FQDNs         []string `json:"fqdns"`
	ResolvedIPs   []string `json:"resolved_ips"` // ✅ NEW
	Justification string   `json:"justification"`
}

type RuleFlat struct {
	Name            string
	Type            string
	Action          string
	Priority        int
	GroupPriority   int
	CollectionPrio  int
	Src             netip.Prefix
	Dst             netip.Prefix
	SrcRaw          string
	DstRaw          string
	Port            string
	Protocol        string
	FQDN            string
	ResolvedIPs     []netip.Addr
	ProcessingOrder int64
	Justified       bool
	Justification   string
}

type Finding struct {
	RuleName        string `tfsdk:"rule_name"`
	Type            string `tfsdk:"type"`
	Status          string `tfsdk:"status"`
	Severity        string `tfsdk:"severity"`
	Message         string `tfsdk:"message"`
	Details         string `tfsdk:"details"`
	ComparedWith    string `tfsdk:"compared_with"`
	ProcessingOrder int64  `tfsdk:"processing_order"`
	Justified       bool   `tfsdk:"justified"`
	Justification   string `tfsdk:"justification"`
	Suggestion      string `tfsdk:"suggestion"`
}

func isPrivateIP(ip netip.Addr) bool {
	return ip.IsPrivate()
}

func isFQDN(s string) bool {
	return strings.Contains(s, ".") && !strings.Contains(s, "/")
}

func resolveFQDNWithDNS(fqdn string, dnsServers []string) []netip.Addr {
	var results []netip.Addr

	for _, dns := range dnsServers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", dns+":53")
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := resolver.LookupIP(ctx, "ip", fqdn)
		cancel()

		if err != nil {
			continue
		}

		for _, ip := range ips {
			addr, err := netip.ParseAddr(ip.String())
			if err == nil {
				results = append(results, addr)
			}
		}

		if len(results) > 0 {
			break
		}
	}

	return results
}

func parseResolvedIPs(ipStrs []string) []netip.Addr {
	var result []netip.Addr
	for _, s := range ipStrs {
		if ip, err := netip.ParseAddr(s); err == nil {
			result = append(result, ip)
		}
	}
	return result
}

func buildRules(p Policy, findings *[]Finding) []RuleFlat {
	var rules []RuleFlat

	for _, rcg := range p.RuleCollectionGroups {

		for _, col := range rcg.AppRuleCollections {
			for _, r := range col.Rules {

				for _, fqdn := range r.FQDNs {

					var resolved []netip.Addr

					// ✅ PRIORITY: JSON > DNS
					if len(r.ResolvedIPs) > 0 {
						resolved = parseResolvedIPs(r.ResolvedIPs)

						// Compare with DNS
						dnsIPs := resolveFQDNWithDNS(fqdn, p.DNSServers)

						if len(dnsIPs) > 0 && !compareIPSets(resolved, dnsIPs) {
							*findings = append(*findings, Finding{
								RuleName:   r.Name,
								Type:       "dns_mismatch",
								Status:     "warning",
								Severity:   "medium",
								Message:    "Resolved IPs differ from DNS",
								Details:    fmt.Sprintf("expected:%v actual:%v", resolved, dnsIPs),
								Suggestion: "Verify DNS consistency",
							})
						}

					} else {
						resolved = resolveFQDNWithDNS(fqdn, p.DNSServers)
					}

					// Private IP check
					for _, ip := range resolved {
						if isPrivateIP(ip) {
							*findings = append(*findings, Finding{
								RuleName:   r.Name,
								Type:       "private_fqdn",
								Status:     "invalid",
								Severity:   "high",
								Message:    "FQDN resolves to private IP",
								Details:    fmt.Sprintf("%s → %s", fqdn, ip),
								Suggestion: "Use network rule",
							})
						}
					}

					rules = append(rules, RuleFlat{
						Name:          r.Name,
						Type:          "app",
						Action:        col.Action,
						Priority:      r.Priority,
						GroupPriority: rcg.Priority,
						CollectionPrio: col.Priority,
						FQDN:          fqdn,
						ResolvedIPs:   resolved,
					})
				}
			}
		}
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	for i := range rules {
		rules[i].ProcessingOrder = int64(i + 1)
	}

	return rules
}

func compareIPSets(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, ip := range a {
		m[ip.String()] = true
	}
	for _, ip := range b {
		if !m[ip.String()] {
			return false
		}
	}
	return true
}

func analyze(p Policy) []Finding {
	var out []Finding
	buildRules(p, &out)
	return out
}