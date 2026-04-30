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
	ResolvedIPs   []string `json:"resolved_ips"`
	Justification string   `json:"justification"`
}

type RuleFlat struct {
	Name           string
	Type           string
	Action         string
	Src            string
	Dst            string
	Port           string
	Protocol       string
	FQDN           string
	IPs            []netip.Addr

	RulePriority   int
	CollectionName string
	CollectionPrio int
	RCGName        string
	RCGPriority    int

	ProcessingOrder int64
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

	ProcessingOrder    int64  `tfsdk:"processing_order"`

	PriorityPath       string `tfsdk:"priority_path"`
	EvaluationPath     string `tfsdk:"evaluation_path"`

	ComparedWith       string `tfsdk:"compared_with"`
	OverlapType        string `tfsdk:"overlap_type"`
	Suggestion         string `tfsdk:"suggestion"`
}

func resolveFQDN(fqdn string, dnsServers []string) []netip.Addr {
	var results []netip.Addr

	for _, dns := range dnsServers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.DialTimeout("udp", dns+":53", 3*time.Second)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := resolver.LookupIP(ctx, "ip", fqdn)
		cancel()

		if err != nil {
			continue
		}

		for _, ip := range ips {
			if addr, err := netip.ParseAddr(ip.String()); err == nil {
				results = append(results, addr)
			}
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

		status := "valid"
		message := "Rule is valid"
		severity := "info"
		overlapType := ""
		var compared string

		for j := 0; j < i; j++ {
			prev := rules[j]

			// App vs Network
			if curr.Type == "app" && prev.Type == "network" {
				for _, ip := range curr.IPs {
					if strings.Contains(prev.Dst, ip.String()) || prev.Dst == "0.0.0.0/0" {

						status = "invalid"
						severity = "high"
						compared = prev.Name

						if prev.Action != curr.Action {
							message = "Conflict (allow vs deny)"
						} else {
							message = "Shadowed by previous rule"
						}
						overlapType = "full"
					}
				}
			}

			// Network vs Network
			if curr.Type == "network" && prev.Type == "network" {
				if curr.Dst == prev.Dst && curr.Port == prev.Port {
					status = "invalid"
					severity = "medium"
					message = "Duplicate rule"
					overlapType = "exact"
					compared = prev.Name
				}
			}
		}

		findings = append(findings, Finding{
			RuleName:           curr.Name,
			Type:               "rule_evaluation",
			Status:             status,
			Severity:           severity,
			Message:            message,

			Source:             curr.Src,
			Destination:        chooseDest(curr),
			Port:               curr.Port,
			Protocol:           curr.Protocol,

			RulePriority:       curr.RulePriority,
			CollectionName:     curr.CollectionName,
			CollectionPriority: curr.CollectionPrio,
			RCGName:            curr.RCGName,
			RCGPriority:        curr.RCGPriority,

			ProcessingOrder:    curr.ProcessingOrder,

			PriorityPath:       buildPriorityPath(curr),
			EvaluationPath:     buildEvaluationPath(curr),

			ComparedWith:       compared,
			OverlapType:        overlapType,
			Suggestion:         suggest(status),
		})
	}

	return findings
}

func chooseDest(r RuleFlat) string {
	if r.Type == "app" {
		return r.FQDN
	}
	return r.Dst
}

func buildPriorityPath(r RuleFlat) string {
	return fmt.Sprintf("RCG(%d) -> COLLECTION(%d) -> RULE(%d)",
		r.RCGPriority,
		r.CollectionPrio,
		r.RulePriority,
	)
}

func buildEvaluationPath(r RuleFlat) string {
	return fmt.Sprintf("RCG[%s:%d] -> COLLECTION[%s:%d] -> RULE[%s:%d]",
		r.RCGName, r.RCGPriority,
		r.CollectionName, r.CollectionPrio,
		r.Name, r.RulePriority,
	)
}

func suggest(status string) string {
	if status == "valid" {
		return "No action needed"
	}
	return "Fix rule ordering or definition"
}