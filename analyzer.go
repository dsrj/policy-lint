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

///////////////////////////
// MODELS
///////////////////////////

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
	Name string
	Type string
	Action string
	Src string
	Dst string
	FQDN string
	IPs []netip.Addr

	Port string
	Protocol string

	RulePriority int
	CollectionName string
	CollectionPrio int
	RCGName string
	RCGPriority int

	ProcessingOrder int64
	Justification string
}

///////////////////////////
// DNS
///////////////////////////

func resolveFQDN(fqdn string, dns []string) []netip.Addr {
	var result []netip.Addr

	for _, d := range dns {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.DialTimeout("udp", d+":53", 3*time.Second)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := r.LookupIP(ctx, "ip", fqdn)
		cancel()

		if err != nil {
			continue
		}

		for _, ip := range ips {
			if addr, err := netip.ParseAddr(ip.String()); err == nil {
				result = append(result, addr)
			}
		}
	}

	return result
}

///////////////////////////
// CIDR ENGINE
///////////////////////////

func parsePrefixSafe(c string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(c)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

func cidrRelation(a, b string) (string, bool) {
	pa, ok1 := parsePrefixSafe(a)
	pb, ok2 := parsePrefixSafe(b)
	if !ok1 || !ok2 {
		return "", false
	}

	if pa == pb {
		return "exact", true
	}
	if pa.Contains(pb.Addr()) && pa.Bits() <= pb.Bits() {
		return "full", true
	}
	if pa.Overlaps(pb) {
		return "partial", true
	}
	return "", false
}

///////////////////////////
// BUILD RULES (WITH IP GROUP EXPANSION)
///////////////////////////

func buildRules(p Policy) []RuleFlat {
	var rules []RuleFlat

	for _, rcg := range p.RuleCollectionGroups {

		for _, col := range rcg.NetworkRuleCollections {
			for _, r := range col.Rules {

				for _, d := range r.Destination {

					// 🔥 IP GROUP EXPANSION
					if group, ok := p.IPGroups[d]; ok {
						for _, cidr := range group {
							rules = append(rules, RuleFlat{
								Name: r.Name,
								Type: "network",
								Action: col.Action,
								Src: strings.Join(r.Source, ","),
								Dst: cidr,
								Port: r.Ports[0],
								Protocol: r.Protocol,
								RulePriority: r.Priority,
								CollectionName: col.Name,
								CollectionPrio: col.Priority,
								RCGName: rcg.Name,
								RCGPriority: rcg.Priority,
								Justification: r.Justification,
							})
						}
						continue
					}

					rules = append(rules, RuleFlat{
						Name: r.Name,
						Type: "network",
						Action: col.Action,
						Src: strings.Join(r.Source, ","),
						Dst: d,
						Port: r.Ports[0],
						Protocol: r.Protocol,
						RulePriority: r.Priority,
						CollectionName: col.Name,
						CollectionPrio: col.Priority,
						RCGName: rcg.Name,
						RCGPriority: rcg.Priority,
						Justification: r.Justification,
					})
				}
			}
		}

		for _, col := range rcg.AppRuleCollections {
			for _, r := range col.Rules {

				for _, fqdn := range r.FQDNs {

					var ips []netip.Addr
					if len(r.ResolvedIPs) > 0 {
						for _, ip := range r.ResolvedIPs {
							addr, _ := netip.ParseAddr(ip)
							ips = append(ips, addr)
						}
					} else {
						ips = resolveFQDN(fqdn, p.DNSServers)
					}

					rules = append(rules, RuleFlat{
						Name: r.Name,
						Type: "app",
						Action: col.Action,
						Src: strings.Join(r.Source, ","),
						FQDN: fqdn,
						IPs: ips,
						RulePriority: r.Priority,
						CollectionName: col.Name,
						CollectionPrio: col.Priority,
						RCGName: rcg.Name,
						RCGPriority: rcg.Priority,
						Justification: r.Justification,
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

///////////////////////////
// ANALYZE (FINAL ENGINE)
///////////////////////////

func analyze(p Policy) []Finding {
	var findings []Finding
	rules := buildRules(p)

	for i := range rules {
		curr := rules[i]

		status := "valid"
		severity := "info"
		message := "Rule is valid"
		var compared string
		overlap := ""

		effective := curr.Action
		hit := curr.Name

		//////////////// VALIDATION //////////////////

		// ❌ Network FQDN
		if curr.Type == "network" && strings.Contains(curr.Dst, ".") && !strings.Contains(curr.Dst, "/") {
			status = "invalid"
			severity = "high"
			message = "FQDN not allowed in network rule"
		}

		// ❌ App private IP
		if curr.Type == "app" {
			for _, ip := range curr.IPs {
				if ip.IsPrivate() {
					status = "invalid"
					severity = "high"
					message = "App rule resolves to private IP"
					break
				}
			}
		}

		//////////////// OVERLAP //////////////////

		for j := 0; j < i; j++ {
			prev := rules[j]

			// App vs Network
			if curr.Type == "app" && prev.Type == "network" {
				for _, ip := range curr.IPs {
					if rel, ok := cidrRelation(prev.Dst, netip.PrefixFrom(ip, 32).String()); ok {
						compared = prev.Name
						effective = prev.Action
						hit = prev.Name

						if prev.Action != curr.Action {
							status = "invalid"
							severity = "high"
							message = "Conflict (blocked by network rule)"
						} else {
							status = "invalid"
							severity = "medium"
							message = "Shadowed by network rule"
						}
						overlap = rel
						break
					}
				}
			}

			// Network vs Network
			if curr.Type == "network" && prev.Type == "network" {
				if rel, ok := cidrRelation(prev.Dst, curr.Dst); ok {
					compared = prev.Name
					effective = prev.Action
					hit = prev.Name

					status = "invalid"
					message = "CIDR overlap"
					severity = "medium"
					overlap = rel
					break
				}
			}
		}

		//////////////// JUSTIFICATION //////////////////

		justified := false
		if curr.Justification != "" && status == "invalid" {
			justified = true
			status = "valid"
			severity = "info"
			message += " (Justified)"
		}

		findings = append(findings, Finding{
			RuleName: curr.Name,
			Type: "rule_evaluation",
			Status: status,
			Severity: severity,
			Message: message,

			Source: curr.Src,
			Destination: chooseDest(curr),
			Port: curr.Port,
			Protocol: curr.Protocol,

			RulePriority: curr.RulePriority,
			CollectionName: curr.CollectionName,
			CollectionPriority: curr.CollectionPrio,
			RCGName: curr.RCGName,
			RCGPriority: curr.RCGPriority,

			ProcessingOrder: curr.ProcessingOrder,
			PriorityPath: buildPriorityPath(curr),
			EvaluationPath: buildEvaluationPath(curr),

			ComparedWith: compared,
			OverlapType: overlap,

			Justified: justified,
			Justification: curr.Justification,

			Suggestion: suggest(status),
			EffectiveAction: effective,
			HitRule: hit,
		})
	}

	return findings
}

///////////////////////////
// HELPERS
///////////////////////////

func chooseDest(r RuleFlat) string {
	if r.Type == "app" {
		return r.FQDN
	}
	return r.Dst
}

func buildPriorityPath(r RuleFlat) string {
	return fmt.Sprintf("RCG(%d)->COL(%d)->RULE(%d)",
		r.RCGPriority, r.CollectionPrio, r.RulePriority)
}

func buildEvaluationPath(r RuleFlat) string {
	return fmt.Sprintf("RCG[%s:%d]->COL[%s:%d]->RULE[%s:%d]",
		r.RCGName, r.RCGPriority,
		r.CollectionName, r.CollectionPrio,
		r.Name, r.RulePriority)
}

func suggest(status string) string {
	if status == "valid" {
		return "No action needed"
	}
	return "Review rule"
}