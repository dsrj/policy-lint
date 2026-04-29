package main

import (
	"fmt"
	"net/netip"
	"strings"
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
	Name          string
	Priority      int
	Action        string
	Src           netip.Prefix
	Dst           netip.Prefix
	Port          string
	Protocol      string
	Justified     bool
	Justification string
}

type Finding struct {
	Type          string `tfsdk:"type"`
	Severity      string `tfsdk:"severity"`
	Message       string `tfsdk:"message"`
	Justified     bool   `tfsdk:"justified"`
	Justification string `tfsdk:"justification"`
	Suggestion    string `tfsdk:"suggestion"`
}

func expand(targets []string, groups map[string][]string) ([]netip.Prefix, []string) {
	var out []netip.Prefix
	var invalid []string

	for _, t := range targets {
		if val, exists := groups[t]; exists {
			for _, ip := range val {
				if p, err := netip.ParsePrefix(ip); err == nil && p.IsValid() {
					out = append(out, p)
				} else {
					invalid = append(invalid, ip)
				}
			}
		} else {
			if p, err := netip.ParsePrefix(t); err == nil && p.IsValid() {
				out = append(out, p)
			} else {
				invalid = append(invalid, t)
			}
		}
	}

	return out, invalid
}

func flatten(p Policy) ([]RuleFlat, []Finding) {
	var result []RuleFlat
	var findings []Finding

	for _, r := range p.NetworkRules {

		if len(r.Ports) == 0 {
			findings = append(findings, Finding{
				Type:          "empty_ports",
				Severity:      "medium",
				Message:       fmt.Sprintf("Rule '%s' has no ports defined.", r.Name),
				Justified:     r.Justification != "",
				Justification: r.Justification,
				Suggestion:    "Define ports or remove rule.",
			})
		}

		for _, port := range r.Ports {
			if port == "*" {
				findings = append(findings, Finding{
					Type:          "overly_permissive",
					Severity:      "high",
					Message:       fmt.Sprintf("Rule '%s' allows all ports.", r.Name),
					Justified:     r.Justification != "",
					Justification: r.Justification,
					Suggestion:    "Restrict ports.",
				})
			}
		}

		srcs, invalidSrc := expand(r.Source, p.IPGroups)
		dsts, invalidDst := expand(r.Destination, p.IPGroups)

		for _, bad := range append(invalidSrc, invalidDst...) {
			findings = append(findings, Finding{
				Type:          "invalid_cidr",
				Severity:      "high",
				Message:       fmt.Sprintf("Rule '%s' has invalid CIDR '%s'.", r.Name, bad),
				Justified:     r.Justification != "",
				Justification: r.Justification,
				Suggestion:    "Fix CIDR format.",
			})
		}

		for _, s := range srcs {
			for _, d := range dsts {
				for _, port := range r.Ports {
					result = append(result, RuleFlat{
						Name:          r.Name,
						Priority:      r.Priority,
						Action:        r.Action,
						Src:           s,
						Dst:           d,
						Port:          port,
						Protocol:      r.Protocol,
						Justified:     r.Justification != "",
						Justification: r.Justification,
					})
				}
			}
		}
	}

	return result, findings
}

func analyze(p Policy) []Finding {
	var f []Finding

	rules, baseFindings := flatten(p)
	f = append(f, baseFindings...)

	seen := map[string]string{}

	for i := 0; i < len(rules); i++ {
		r1 := rules[i]

		key := fmt.Sprintf("%s|%s|%s|%s|%s",
			r1.Src, r1.Dst, r1.Port, r1.Protocol, r1.Action)

		if prev, exists := seen[key]; exists {
			f = append(f, Finding{
				Type:          "duplicate",
				Severity:      "medium",
				Message:       fmt.Sprintf("Rule '%s' duplicates '%s'.", r1.Name, prev),
				Justified:     r1.Justified,
				Justification: r1.Justification,
				Suggestion:    "Remove duplicate.",
			})
		} else {
			seen[key] = r1.Name
		}

		for j := i + 1; j < len(rules); j++ {
			r2 := rules[j]

			if r1.Priority > r2.Priority {
				r1, r2 = r2, r1
			}

			if r1.Protocol != r2.Protocol && r1.Protocol != "Any" && r2.Protocol != "Any" {
				f = append(f, Finding{
					Type:          "protocol_mismatch",
					Severity:      "low",
					Message:       fmt.Sprintf("Rules '%s' and '%s' use different protocols.", r1.Name, r2.Name),
					Justified:     r2.Justified,
					Justification: r2.Justification,
					Suggestion:    "Align protocol.",
				})
			}

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
					Type:          "shadowed",
					Severity:      sev,
					Message:       fmt.Sprintf("Rule '%s' is shadowed by '%s'.", r2.Name, r1.Name),
					Justified:     r2.Justified,
					Justification: r2.Justification,
					Suggestion:    "Adjust priority.",
				})
			}
		}
	}

	for _, r := range p.AppRules {
		for _, fqdn := range r.FQDNs {

			if fqdn == "*" {
				f = append(f, Finding{
					Type:          "wildcard",
					Severity:      "high",
					Message:       fmt.Sprintf("Rule '%s' allows all domains.", r.Name),
					Justified:     r.Justification != "",
					Justification: r.Justification,
					Suggestion:    "Restrict domains.",
				})
			}

			if strings.Contains(fqdn, "://") {
				f = append(f, Finding{
					Type:          "invalid_fqdn",
					Severity:      "medium",
					Message:       fmt.Sprintf("Rule '%s' has invalid FQDN '%s'.", r.Name, fqdn),
					Justified:     r.Justification != "",
					Justification: r.Justification,
					Suggestion:    "Fix domain format.",
				})
			}
		}
	}

	return f
}