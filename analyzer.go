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

type RuleFlat struct {
	Name          string
	Priority      int
	Action        string
	Src           netip.Prefix
	Dst           netip.Prefix
	SrcRaw        string
	DstRaw        string
	Port          string
	Protocol      string
	Justified     bool
	Justification string
}

type Finding struct {
	RuleName      string `tfsdk:"rule_name"`
	Type          string `tfsdk:"type"`
	Severity      string `tfsdk:"severity"`
	Status        string `tfsdk:"status"`
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

func expand(targets []string, groups map[string][]string) ([]netip.Prefix, []string, []string) {
	var out []netip.Prefix
	var invalid []string
	var raw []string

	for _, t := range targets {
		if val, exists := groups[t]; exists {
			for _, ip := range val {
				if p, err := netip.ParsePrefix(ip); err == nil && p.IsValid() {
					out = append(out, p)
					raw = append(raw, fmt.Sprintf("%s(%s)", t, ip))
				} else {
					invalid = append(invalid, ip)
				}
			}
		} else {
			if p, err := netip.ParsePrefix(t); err == nil && p.IsValid() {
				out = append(out, p)
				raw = append(raw, t)
			} else {
				invalid = append(invalid, t)
			}
		}
	}

	return out, invalid, raw
}

func flatten(p Policy) ([]RuleFlat, []Finding) {
	var result []RuleFlat
	var findings []Finding

	for _, r := range p.NetworkRules {

		srcs, invalidSrc, rawSrc := expand(r.Source, p.IPGroups)
		dsts, invalidDst, rawDst := expand(r.Destination, p.IPGroups)

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
				Suggestion:    "Fix CIDR",
			})
		}

		for i, s := range srcs {
			for j, d := range dsts {
				for _, port := range r.Ports {

					result = append(result, RuleFlat{
						Name:          r.Name,
						Priority:      r.Priority,
						Action:        r.Action,
						Src:           s,
						Dst:           d,
						SrcRaw:        rawSrc[i],
						DstRaw:        rawDst[j],
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

func ruleDetails(r RuleFlat) string {
	return fmt.Sprintf(
		"src:%s dst:%s port:%s protocol:%s priority:%d action:%s",
		r.SrcRaw, r.DstRaw, r.Port, r.Protocol, r.Priority, r.Action,
	)
}

func analyze(p Policy) []Finding {
	var f []Finding

	rules, base := flatten(p)
	f = append(f, base...)

	seen := map[string]string{}
	validMap := map[string]bool{}

	for _, r := range rules {
		validMap[r.Name] = true
	}

	for i := 0; i < len(rules); i++ {
		r1 := rules[i]

		key := fmt.Sprintf("%s|%s|%s|%s|%s",
			r1.Src, r1.Dst, r1.Port, r1.Protocol, r1.Action)

		if prev, exists := seen[key]; exists {
			validMap[r1.Name] = false

			f = append(f, Finding{
				RuleName:      r1.Name,
				Type:          "duplicate",
				Status:        "invalid",
				Severity:      "medium",
				Message:       "Duplicate rule",
				Details:       ruleDetails(r1),
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

			// CIDR comparison details
			cidrCompare := fmt.Sprintf(
				"%s contains %s = %v | %s contains %s = %v",
				a.Src, b.Src, a.Src.Contains(b.Src.Addr()),
				a.Dst, b.Dst, a.Dst.Contains(b.Dst.Addr()),
			)

			if a.Protocol != b.Protocol && a.Protocol != "Any" && b.Protocol != "Any" {
				validMap[b.Name] = false

				f = append(f, Finding{
					RuleName:      b.Name,
					Type:          "protocol_mismatch",
					Status:        "invalid",
					Severity:      "low",
					Message:       "Protocol mismatch",
					Details:       fmt.Sprintf("%s | %s", ruleDetails(b), cidrCompare),
					ComparedWith:  a.Name,
					Justified:     b.Justified,
					Justification: b.Justification,
					Suggestion:    "Align protocol",
				})
			}

			if a.Src.Contains(b.Src.Addr()) &&
				a.Dst.Contains(b.Dst.Addr()) &&
				a.Port == b.Port {

				validMap[b.Name] = false

				f = append(f, Finding{
					RuleName:      b.Name,
					Type:          "shadowed",
					Status:        "invalid",
					Severity:      "high",
					Message:       "Rule is shadowed",
					Details:       fmt.Sprintf("%s | compared with %s | %s", ruleDetails(b), ruleDetails(a), cidrCompare),
					ComparedWith:  a.Name,
					Justified:     b.Justified,
					Justification: b.Justification,
					Suggestion:    "Adjust priority",
				})
			}
		}
	}

	// VALID rules with FULL details
	for _, r := range rules {
		if validMap[r.Name] {
			f = append(f, Finding{
				RuleName:      r.Name,
				Type:          "valid",
				Status:        "valid",
				Severity:      "info",
				Message:       "Rule is valid",
				Details:       ruleDetails(r),
				Justified:     r.Justified,
				Justification: r.Justification,
				Suggestion:    "No action needed",
			})
		}
	}

	return f
}