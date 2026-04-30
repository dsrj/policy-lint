package main

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

	Justified          bool   `tfsdk:"justified"`
	Justification      string `tfsdk:"justification"`

	Suggestion         string `tfsdk:"suggestion"`

	EffectiveAction    string `tfsdk:"effective_action"`
	HitRule            string `tfsdk:"hit_rule"`
}