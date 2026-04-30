package main

import (
	"fmt"
	"net/netip"
	"sort"
)

type Policy struct {
	IPGroups             map[string][]string   `json:"ip_groups"`
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
	ProcessingOrder int
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
	ProcessingOrder int    `tfsdk:"processing_order"`
	Justified       bool   `tfsdk:"justified"`
	Justification   string `tfsdk:"justification"`
	Suggestion      string `tfsdk:"suggestion"`
}

func expand(targets []string, groups map[string][]string) ([]netip.Prefix, []string) {
	var out []netip.Prefix
	var raw []string

	for _, t := range targets {
		if val, ok := groups[t]; ok {
			for _, ip := range val {
				if p, err := netip.ParsePrefix(ip); err == nil {
					out = append(out, p)
					raw = append(raw, fmt.Sprintf("%s(%s)", t, ip))
				}
			}
		} else {
			if p, err := netip.ParsePrefix(t); err == nil {
				out = append(out, p)
				raw = append(raw, t)
			}
		}
	}
	return out, raw
}

func buildRules(p Policy) []RuleFlat {
	var rules []RuleFlat

	for _, rcg := range p.RuleCollectionGroups {

		// NETWORK RULES
		for _, col := range rcg.NetworkRuleCollections {
			for _, r := range col.Rules {

				srcs, srcRaw := expand(r.Source, p.IPGroups)
				dsts, dstRaw := expand(r.Destination, p.IPGroups)

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

		// APP RULES
		for _, col := range rcg.AppRuleCollections {
			for _, r := range col.Rules {

				srcs, srcRaw := expand(r.Source, p.IPGroups)

				for i, s := range srcs {
					for _, fqdn := range r.FQDNs {

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
							Protocol:       "HTTP/HTTPS",
							Justified:      r.Justification != "",
							Justification:  r.Justification,
						})
					}
				}
			}
		}
	}

	// 🔥 SORT LIKE AZURE
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
		rules[i].ProcessingOrder = i + 1
	}

	return rules
}

func details(r RuleFlat) string {
	if r.Type == "network" {
		return fmt.Sprintf(
			"[#%d] %s src:%s dst:%s port:%s proto:%s action:%s (rcg:%d col:%d rule:%d)",
			r.ProcessingOrder, r.Type, r.SrcRaw, r.DstRaw, r.Port, r.Protocol, r.Action,
			r.GroupPriority, r.CollectionPrio, r.Priority,
		)
	}
	return fmt.Sprintf(
		"[#%d] %s src:%s fqdn:%s action:%s (rcg:%d col:%d rule:%d)",
		r.ProcessingOrder, r.Type, r.SrcRaw, r.FQDN, r.Action,
		r.GroupPriority, r.CollectionPrio, r.Priority,
	)
}

func analyze(p Policy) []Finding {
	var out []Finding
	rules := buildRules(p)

	for i := range rules {
		curr := rules[i]
		valid := true

		for j := 0; j < i; j++ {
			prev := rules[j]

			if curr.Type != prev.Type {
				continue
			}

			// NETWORK MATCH
			if curr.Type == "network" {
				if prev.Src.Contains(curr.Src.Addr()) &&
					prev.Dst.Contains(curr.Dst.Addr()) &&
					prev.Port == curr.Port {

					valid = false

					out = append(out, Finding{
						RuleName:        curr.Name,
						Type:            "shadowed",
						Status:          "invalid",
						Severity:        "high",
						Message:         "Shadowed by earlier rule",
						Details:         fmt.Sprintf("%s blocked by %s", details(curr), details(prev)),
						ComparedWith:    prev.Name,
						ProcessingOrder: curr.ProcessingOrder,
						Justified:       curr.Justified,
						Justification:   curr.Justification,
						Suggestion:      "Move rule earlier or narrow match",
					})
					break
				}
			}

			// APP MATCH
			if curr.Type == "app" {
				if prev.FQDN == "*" {
					valid = false

					out = append(out, Finding{
						RuleName:        curr.Name,
						Type:            "shadowed",
						Status:          "invalid",
						Severity:        "high",
						Message:         "Wildcard rule blocks this rule",
						Details:         fmt.Sprintf("%s blocked by %s", details(curr), details(prev)),
						ComparedWith:    prev.Name,
						ProcessingOrder: curr.ProcessingOrder,
						Justified:       curr.Justified,
						Justification:   curr.Justification,
						Suggestion:      "Avoid wildcard before specific rules",
					})
					break
				}
			}
		}

		if valid {
			out = append(out, Finding{
				RuleName:        curr.Name,
				Type:            "valid",
				Status:          "valid",
				Severity:        "info",
				Message:         "Rule is effective",
				Details:         details(curr),
				ProcessingOrder: curr.ProcessingOrder,
				Justified:       curr.Justified,
				Justification:   curr.Justification,
				Suggestion:      "No action needed",
			})
		}
	}

	return out
}