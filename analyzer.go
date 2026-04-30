package main

import (
	"context"
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
	ResolvedIPs   []string `json:"resolved_ips"`
	Justification string   `json:"justification"`
}

type RuleFlat struct {
	Name            string
	Type            string
	Action          string
	Src             string
	Dst             string
	Port            string
	Protocol        string
	FQDN            string
	IPs             []netip.Addr

	RulePriority    int
	CollectionName  string
	CollectionPrio  int
	RCGName         string
	RCGPriority     int

	ProcessingOrder int64
	Justified       bool
	Justification   string
}

type Finding struct {
	RuleName           string `tfsdk:"rule_name"`
	Type               string `tfsdk:"type"`
	Status             string `tfsdk:"status"`
	Severity           string `tfsdk:"severity"`
	Message            string `tfsdk:"message"`

	Source             string `tfsdk:"source"`
	Destination        string `tfsdk:"destination"`
	Port               string `tfsdk:"port"`
	Protocol           string `tfsdk:"protocol"`

	RulePriority       int    `tfsdk:"rule_priority"`
	CollectionName     string `tfsdk:"collection_name"`
	CollectionPriority int    `tfsdk:"collection_priority"`
	RCGName            string `tfsdk:"rcg_name"`
	RCGPriority        int    `tfsdk:"rcg_priority"`

	ComparedWith       string `tfsdk:"compared_with"`
	ProcessingOrder    int64  `tfsdk:"processing_order"`

	Justified          bool   `tfsdk:"justified"`
	Justification      string `tfsdk:"justification"`
	Suggestion         string `tfsdk:"suggestion"`
}

func resolveFQDN(fqdn string, dnsServers []string) []netip.Addr {
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

func parseIPs(strs []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range strs {
		if ip, err := netip.ParseAddr(s); err == nil {
			out = append(out, ip)
		}
	}
	return out
}

func buildRules(p Policy) []RuleFlat {
	var rules []RuleFlat

	for _, rcg := range p.RuleCollectionGroups {

		for _, col := range rcg.NetworkRuleCollections {
			for _, r := range col.Rules {
				for _, s := range r.Source {
					for _, d := range r.Destination {
						for _, port := range r.Ports {

							rules = append(rules, RuleFlat{
								Name:           r.Name,
								Type:           "network",
								Action:         col.Action,
								Src:            s,
								Dst:            d,
								Port:           port,
								Protocol:       r.Protocol,

								RulePriority:   r.Priority,
								CollectionName: col.Name,
								CollectionPrio: col.Priority,
								RCGName:        rcg.Name,
								RCGPriority:    rcg.Priority,

								Justified:      r.Justification != "",
								Justification:  r.Justification,
							})
						}
					}
				}
			}
		}

		for _, col := range rcg.AppRuleCollections {
			for _, r := range col.Rules {

				for _, fqdn := range r.FQDNs {

					var ips []netip.Addr
					if len(r.ResolvedIPs) > 0 {
						ips = parseIPs(r.ResolvedIPs)
					} else {
						ips = resolveFQDN(fqdn, p.DNSServers)
					}

					rules = append(rules, RuleFlat{
						Name:           r.Name,
						Type:           "app",
						Action:         col.Action,
						Src:            strings.Join(r.Source, ","),
						FQDN:           fqdn,
						IPs:            ips,

						RulePriority:   r.Priority,
						CollectionName: col.Name,
						CollectionPrio: col.Priority,
						RCGName:        rcg.Name,
						RCGPriority:    rcg.Priority,

						Justified:      r.Justification != "",
						Justification:  r.Justification,
					})
				}
			}
		}
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].RCGPriority != rules[j].RCGPriority {
			return rules[i].RCGPriority < rules[j].RCGPriority
		}
		if rules[i].CollectionPrio != rules[j].CollectionPrio {
			return rules[i].CollectionPrio < rules[j].CollectionPrio
		}
		return rules[i].RulePriority < rules[j].RulePriority
	})

	for i := range rules {
		rules[i].ProcessingOrder = int64(i + 1)
	}

	return rules
}

func analyze(p Policy) []Finding {
	var findings []Finding
	rules := buildRules(p)

	for i := range rules {
		curr := rules[i]

		for j := 0; j < i; j++ {
			prev := rules[j]

			if curr.Type == "app" && prev.Type == "network" {

				for _, ip := range curr.IPs {

					if strings.Contains(prev.Dst, ip.String()) || prev.Dst == "0.0.0.0/0" {

						msg := "FQDN overlaps with network rule"
						if prev.Action != curr.Action {
							msg = "Conflict between app and network rule"
						}

						findings = append(findings, Finding{
							RuleName:           curr.Name,
							Type:               "fqdn_network_overlap",
							Status:             "invalid",
							Severity:           "high",
							Message:            msg,

							Source:             curr.Src,
							Destination:        curr.FQDN,
							Port:               curr.Port,
							Protocol:           curr.Protocol,

							RulePriority:       curr.RulePriority,
							CollectionName:     curr.CollectionName,
							CollectionPriority: curr.CollectionPrio,
							RCGName:            curr.RCGName,
							RCGPriority:        curr.RCGPriority,

							ComparedWith:       prev.Name,
							ProcessingOrder:    curr.ProcessingOrder,

							Justified:          curr.Justified,
							Justification:      curr.Justification,
							Suggestion:         "Review rule ordering or remove overlap",
						})
					}
				}
			}
		}
	}

	return findings
}