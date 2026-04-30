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

func expand(targets []string, groups map[string][]string) ([]netip.Prefix, []string, []string) {
	var out []netip.Prefix
	var raw []string
	var fqdns []string

	for _, t := range targets {
		if val, ok := groups[t]; ok {
			for _, ip := range val {
				if p, err := netip.ParsePrefix(ip); err == nil {
					out = append(out, p)
					raw = append(raw, fmt.Sprintf("%s(%s)", t, ip))
				}
			}
		} else if isFQDN(t) {
			fqdns = append(fqdns, t)
		} else {
			if p, err := netip.ParsePrefix(t); err == nil {
				out = append(out, p)
				raw = append(raw, t)
			}
		}
	}
	return out, raw, fqdns
}

func buildRules(p Policy, findings *[]Finding) []RuleFlat {
	var rules []RuleFlat

	for _, rcg := range p.RuleCollectionGroups {

		for _, col := range rcg.NetworkRuleCollections {
			for _, r := range col.Rules {

				srcs, srcRaw, srcFQDN := expand(r.Source, p.IPGroups)
				dsts, dstRaw, dstFQDN := expand(r.Destination, p.IPGroups)

				// 🚨 FQDN in network rule detection
				if len(srcFQDN) > 0 || len(dstFQDN) > 0 {
					status := "invalid"
					msg := "FQDN used in network rule causes SNAT issue"

					if r.Justification != "" {
						status = "valid"
						msg = "FQDN allowed due to justification"
					}

					*findings = append(*findings, Finding{
						RuleName:      r.Name,
						Type:          "fqdn_in_network_rule",
						Status:        status,
						Severity:      "high",
						Message:       msg,
						Details:       fmt.Sprintf("FQDN detected: %v %v", srcFQDN, dstFQDN),
						Justified:     r.Justification != "",
						Justification: r.Justification,
						Suggestion:    "Use IP instead of FQDN",
					})
				}

				for i, s := range srcs {
					for j, d := range dsts {
						for _, port := range r.Ports {

							rules = append(rules, RuleFlat{
								Name:           r.Name,
								Type:           "network",
								Action:         col.Action,
								Priority:       r.Priority,
								GroupPriority:  rcg.Priority,
								CollectionPrio: col.Priority,
								Src:            s,
								Dst:            d,
								SrcRaw:         srcRaw[i],
								DstRaw:         dstRaw[j],
								Port:           port,
								Protocol:       r.Protocol,
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

				srcs, srcRaw, _ := expand(r.Source, p.IPGroups)

				for i, s := range srcs {
					for _, fqdn := range r.FQDNs {

						ips := resolveFQDNWithDNS(fqdn, p.DNSServers)

						// 🚨 PRIVATE IP CHECK
						for _, ip := range ips {
							if isPrivateIP(ip) {
								*findings = append(*findings, Finding{
									RuleName:      r.Name,
									Type:          "private_fqdn",
									Status:        "invalid",
									Severity:      "high",
									Message:       "FQDN resolves to private IP",
									Details:       fmt.Sprintf("%s resolves to %s", fqdn, ip),
									Justified:     r.Justification != "",
									Justification: r.Justification,
									Suggestion:    "Convert to network rule",
								})
							}
						}

						rules = append(rules, RuleFlat{
							Name:           r.Name,
							Type:           "app",
							Action:         col.Action,
							Priority:       r.Priority,
							GroupPriority:  rcg.Priority,
							CollectionPrio: col.Priority,
							Src:            s,
							SrcRaw:         srcRaw[i],
							FQDN:           fqdn,
							ResolvedIPs:    ips,
							Protocol:       "HTTP/HTTPS",
							Justified:      r.Justification != "",
							Justification:  r.Justification,
						})
					}
				}
			}
		}
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].GroupPriority != rules[j].GroupPriority {
			return rules[i].GroupPriority < rules[j].GroupPriority
		}
		if rules[i].CollectionPrio != rules[j].CollectionPrio {
			return rules[i].CollectionPrio < rules[j].CollectionPrio
		}
		return rules[i].Priority < rules[j].Priority
	})

	for i := range rules {
		rules[i].ProcessingOrder = int64(i + 1)
	}

	return rules
}

func analyze(p Policy) []Finding {
	var out []Finding

	rules := buildRules(p, &out)

	for _, r := range rules {
		out = append(out, Finding{
			RuleName:        r.Name,
			Type:            "valid",
			Status:          "valid",
			Severity:        "info",
			Message:         "Rule is valid",
			Details:         fmt.Sprintf("processed order %d", r.ProcessingOrder),
			ProcessingOrder: r.ProcessingOrder,
			Justified:       r.Justified,
			Justification:   r.Justification,
			Suggestion:      "No action needed",
		})
	}

	return out
}