package main

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type analysisDataSource struct{}

// ✅ Ensure interface is fully implemented (prevents runtime crash)
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
						"type":      datasourceschema.StringAttribute{Computed: true},
						"severity":  datasourceschema.StringAttribute{Computed: true},
						"message":   datasourceschema.StringAttribute{Computed: true},
						"justified": datasourceschema.BoolAttribute{Computed: true},
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

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// ✅ Prevent crash if value is null or unknown
	if data.PolicyJSON.IsNull() || data.PolicyJSON.IsUnknown() {
		return
	}

	var policy Policy
	if err := json.Unmarshal([]byte(data.PolicyJSON.ValueString()), &policy); err != nil {
		resp.Diagnostics.AddError("JSON Error", err.Error())
		return
	}

	// ✅ Protect against runtime panic in analyzer
	defer func() {
		if r := recover(); r != nil {
			resp.Diagnostics.AddError("Analyzer Panic", "Analyzer crashed during execution")
		}
	}()

	data.Findings = analyze(policy)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
