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
	RuleName      string `tfsdk:"rule_name"`
	Type          string `tfsdk:"type"`
	Severity      string `tfsdk:"severity"`
	Status        string `tfsdk:"status"` // valid / invalid
	Message       string `tfsdk:"message"`
	Details       string `tfsdk:"details"`
	ComparedWith  string `tfsdk:"compared_with"`
	Justified     bool   `tfsdk:"justified"`
	Justification string `tfsdk:"justification"`
	Suggestion    string `tfsdk:"suggestion"`
}

func overlaps(r1, r2 RuleFlat) bool {
	return r1.Src.Overlaps(r2.Src) && r1.Dst.Overlaps(r2.Dst)
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
				RuleName:      r.Name,
				Type:          "empty_ports",
				Status:        "invalid",
				Severity:      "medium",
				Message:       "No ports defined",
				Details:       "ports: []",
				Justified:     r.Justification != "",
				Justification: r.Justification,
				Suggestion:    "Define ports or remove rule",
			})
		}

		for _, port := range r.Ports {
			if port == "*" {
				findings = append(findings, Finding{
					RuleName:      r.Name,
					Type:          "overly_permissive",
					Status:        "invalid",
					Severity:      "high",
					Message:       "Allows all ports",
					Details:       "ports: *",
					Justified:     r.Justification != "",
					Justification: r.Justification,
					Suggestion:    "Restrict ports",
				})
			}
		}

		srcs, invalidSrc := expand(r.Source, p.IPGroups)
		dsts, invalidDst := expand(r.Destination, p.IPGroups)

		for _, bad := range append(invalidSrc, invalidDst...) {
			findings = append(findings, Finding{
				RuleName:      r.Name,
				Type:          "invalid_cidr",
				Status:        "invalid",
				Severity:      "high",
				Message:       "Invalid CIDR",
				Details:       bad,
				Justified:     r.Justification != "",
				Justification: r.Justification,
				Suggestion:    "Fix CIDR format",
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
	ruleValidity := map[string]bool{}

	for _, r := range rules {
		ruleValidity[r.Name] = true
	}

	for i := 0; i < len(rules); i++ {
		r1 := rules[i]

		key := fmt.Sprintf("%s|%s|%s|%s|%s",
			r1.Src, r1.Dst, r1.Port, r1.Protocol, r1.Action)

		if prev, exists := seen[key]; exists {
			ruleValidity[r1.Name] = false
			f = append(f, Finding{
				RuleName:      r1.Name,
				Type:          "duplicate",
				Status:        "invalid",
				Severity:      "medium",
				Message:       "Duplicate rule",
				Details:       key,
				ComparedWith:  prev,
				Justified:     r1.Justified,
				Justification: r1.Justification,
				Suggestion:    "Remove duplicate",
			})
		} else {
			seen[key] = r1.Name
		}

		for j := i + 1; j < len(rules); j++ {
			r2 := rules[j]

			if !overlaps(r1, r2) {
				continue
			}

			a, b := r1, r2
			if a.Priority > b.Priority {
				a, b = b, a
			}

			if a.Protocol != b.Protocol && a.Protocol != "Any" && b.Protocol != "Any" {
				ruleValidity[b.Name] = false
				f = append(f, Finding{
					RuleName:      b.Name,
					Type:          "protocol_mismatch",
					Status:        "invalid",
					Severity:      "low",
					Message:       "Protocol mismatch",
					Details:       fmt.Sprintf("%s=%s vs %s=%s", a.Name, a.Protocol, b.Name, b.Protocol),
					ComparedWith:  a.Name,
					Justified:     b.Justified,
					Justification: b.Justification,
					Suggestion:    "Align protocol",
				})
			}

			if a.Src.Contains(b.Src.Addr()) &&
				a.Dst.Contains(b.Dst.Addr()) &&
				a.Port == b.Port {

				ruleValidity[b.Name] = false

				sev := "medium"
				if a.Action != b.Action {
					sev = "high"
				}

				f = append(f, Finding{
					RuleName:      b.Name,
					Type:          "shadowed",
					Status:        "invalid",
					Severity:      sev,
					Message:       "Rule is shadowed",
					Details:       fmt.Sprintf("src:%s dst:%s port:%s", b.Src, b.Dst, b.Port),
					ComparedWith:  a.Name,
					Justified:     b.Justified,
					Justification: b.Justification,
					Suggestion:    "Adjust priority",
				})
			}
		}
	}

	for _, r := range p.AppRules {
		for _, fqdn := range r.FQDNs {

			if fqdn == "*" {
				ruleValidity[r.Name] = false
				f = append(f, Finding{
					RuleName:      r.Name,
					Type:          "wildcard",
					Status:        "invalid",
					Severity:      "high",
					Message:       "Allows all domains",
					Details:       "*",
					Justified:     r.Justification != "",
					Justification: r.Justification,
					Suggestion:    "Restrict domains",
				})
			}

			if strings.Contains(fqdn, "://") {
				ruleValidity[r.Name] = false
				f = append(f, Finding{
					RuleName:      r.Name,
					Type:          "invalid_fqdn",
					Status:        "invalid",
					Severity:      "medium",
					Message:       "Invalid FQDN",
					Details:       fqdn,
					Justified:     r.Justification != "",
					Justification: r.Justification,
					Suggestion:    "Fix domain",
				})
			}
		}
	}

	// Add VALID rules
	for rule, valid := range ruleValidity {
		if valid {
			f = append(f, Finding{
				RuleName: rule,
				Type:     "valid",
				Status:   "valid",
				Severity: "info",
				Message:  "Rule is valid",
			})
		}
	}

	return f
}