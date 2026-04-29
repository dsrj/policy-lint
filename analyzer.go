package main

import (
	"fmt"
	"net/netip"
)

type Policy struct {
	IPGroups     map[string][]string `json:"ip_groups"`
	NetworkRules []NetworkRule       `json:"network_rules"`
	AppRules     []AppRule           `json:"app_rules"`
}

type NetworkRule struct {
	Name          string   `json:"name"`
	Priority      int      `json:"priority"`
	Action        string   `json:"action"`
	Source        []string `json:"source"`
	Destination   []string `json:"destination"`
	Ports         []string `json:"ports"`
	Protocol      string   `json:"protocol"`
	Justification string   `json:"justification"`
}

type AppRule struct {
	Name          string   `json:"name"`
	Priority      int      `json:"priority"`
	Action        string   `json:"action"`
	Source        []string `json:"source"`
	FQDNs         []string `json:"fqdns"`
	Justification string   `json:"justification"`
}

type RuleFlat struct {
	Name      string
	Priority  int
	Action    string
	Src       netip.Prefix
	Dst       netip.Prefix
	Port      string
	Protocol  string
	Justified bool
}

type Finding struct {
	Type      string `tfsdk:"type"`
	Severity  string `tfsdk:"severity"`
	Message   string `tfsdk:"message"`
	Justified bool   `tfsdk:"justified"`
}

func expand(targets []string, groups map[string][]string) []netip.Prefix {
	var out []netip.Prefix
	for _, t := range targets {
		if val, exists := groups[t]; exists {
			for _, ip := range val {
				if p, err := netip.ParsePrefix(ip); err == nil {
					out = append(out, p)
				}
			}
		} else {
			if p, err := netip.ParsePrefix(t); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

func flatten(p Policy) []RuleFlat {
	var result []RuleFlat
	for _, r := range p.NetworkRules {
		srcs := expand(r.Source, p.IPGroups)
		dsts := expand(r.Destination, p.IPGroups)
		for _, s := range srcs {
			for _, d := range dsts {
				for _, port := range r.Ports {
					result = append(result, RuleFlat{
						Name: r.Name, Priority: r.Priority, Action: r.Action,
						Src: s, Dst: d, Port: port, Protocol: r.Protocol,
						Justified: r.Justification != "",
					})
				}
			}
		}
	}
	return result
}

func analyze(p Policy) []Finding {
	var f []Finding
	rules := flatten(p)

	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			r1, r2 := rules[i], rules[j]

			if r1.Priority > r2.Priority {
				r1, r2 = r2, r1
			}

			// ✅ SAFE Shadow check (prevents panic)
			if r1.Src.IsValid() && r2.Src.IsValid() &&
				r1.Dst.IsValid() && r2.Dst.IsValid() &&
				r1.Src.Contains(r2.Src.Addr()) &&
				r1.Dst.Contains(r2.Dst.Addr()) &&
				r1.Port == r2.Port {

				sev := "medium"
				if r1.Action != r2.Action {
					sev = "high"
				}

				f = append(f, Finding{
					Type:      "shadowed",
					Severity:  sev,
					Message:   fmt.Sprintf("%s shadowed by %s", r2.Name, r1.Name),
					Justified: r2.Justified,
				})
			}
		}
	}

	for _, r := range p.AppRules {
		for _, fqdn := range r.FQDNs {
			if fqdn == "*" {
				f = append(f, Finding{
					Type:      "wildcard",
					Severity:  "high",
					Message:   r.Name + " has * wildcard",
					Justified: r.Justification != "",
				})
			}
		}
	}

	return f
}
