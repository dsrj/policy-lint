package main

import (
	"context"
	"encoding/json"

	"://github.com"
	"://github.com/schema"
	"://github.com"
)

type analysisDataSource struct{}

func NewAnalysisDataSource() datasource.DataSource {
	return &analysisDataSource{}
}

func (d *analysisDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_analysis"
}

func (d *analysisDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"policy_json": schema.StringAttribute{
				Required: true,
			},
			"findings": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type":      schema.StringAttribute{Computed: true},
						"severity":  schema.StringAttribute{Computed: true},
						"message":   schema.StringAttribute{Computed: true},
						"justified": schema.BoolAttribute{Computed: true},
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

	var policy Policy
	if err := json.Unmarshal([]byte(data.PolicyJSON.ValueString()), &policy); err != nil {
		resp.Diagnostics.AddError("JSON Error", err.Error())
		return
	}

	data.Findings = analyze(policy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
