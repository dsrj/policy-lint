package main

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type analysisDataSource struct{}

var _ datasource.DataSource = &analysisDataSource{}

func NewAnalysisDataSource() datasource.DataSource {
	return &analysisDataSource{}
}

func (d *analysisDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_analysis"
}

func (d *analysisDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = datasourceschema.Schema{
		Attributes: map[string]datasourceschema.Attribute{

			"policy_json": datasourceschema.StringAttribute{
				Required: true,
			},

			"findings": datasourceschema.ListNestedAttribute{
				Computed: true,
				NestedObject: datasourceschema.NestedAttributeObject{
					Attributes: map[string]datasourceschema.Attribute{

						// Core
						"rule_name": datasourceschema.StringAttribute{Computed: true},
						"type":      datasourceschema.StringAttribute{Computed: true},
						"status":    datasourceschema.StringAttribute{Computed: true},
						"severity":  datasourceschema.StringAttribute{Computed: true},
						"message":   datasourceschema.StringAttribute{Computed: true},

						// Traffic details
						"source":      datasourceschema.StringAttribute{Computed: true},
						"destination": datasourceschema.StringAttribute{Computed: true},
						"port":        datasourceschema.StringAttribute{Computed: true},
						"protocol":    datasourceschema.StringAttribute{Computed: true},

						// Priority
						"rule_priority":       datasourceschema.Int64Attribute{Computed: true},
						"collection_name":     datasourceschema.StringAttribute{Computed: true},
						"collection_priority": datasourceschema.Int64Attribute{Computed: true},
						"rcg_name":            datasourceschema.StringAttribute{Computed: true},
						"rcg_priority":        datasourceschema.Int64Attribute{Computed: true},

						"processing_order": datasourceschema.Int64Attribute{Computed: true},

						// Evaluation path
						"priority_path":   datasourceschema.StringAttribute{Computed: true},
						"evaluation_path": datasourceschema.StringAttribute{Computed: true},

						// Comparison
						"compared_with": datasourceschema.StringAttribute{Computed: true},
						"overlap_type":  datasourceschema.StringAttribute{Computed: true},

						// Justification
						"justified":     datasourceschema.BoolAttribute{Computed: true},
						"justification": datasourceschema.StringAttribute{Computed: true},

						// Outcome (🔥 FIXED — added)
						"effective_action": datasourceschema.StringAttribute{Computed: true},
						"hit_rule":         datasourceschema.StringAttribute{Computed: true},

						// Recommendation
						"suggestion": datasourceschema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *analysisDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {

	var data struct {
		PolicyJSON types.String `tfsdk:"policy_json"`
		Findings   []Finding    `tfsdk:"findings"`
	}

	// Read input
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.PolicyJSON.IsNull() || data.PolicyJSON.IsUnknown() {
		return
	}

	// Parse JSON
	var policy Policy
	if err := json.Unmarshal([]byte(data.PolicyJSON.ValueString()), &policy); err != nil {
		resp.Diagnostics.AddError("Invalid JSON", err.Error())
		return
	}

	// Safety against panic
	defer func() {
		if r := recover(); r != nil {
			resp.Diagnostics.AddError("Analyzer Panic", "Analyzer crashed unexpectedly")
		}
	}()

	// Run analysis
	data.Findings = analyze(policy)

	// Save state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}