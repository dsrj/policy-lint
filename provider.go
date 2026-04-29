package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = &fwProvider{}

type fwProvider struct{}

func NewProvider() provider.Provider {
	return &fwProvider{}
}

func (p *fwProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "fw-analyzer"
}

func (p *fwProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = provider.Schema{}
}

func (p *fwProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {}

func (p *fwProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{NewAnalysisDataSource}
}

func (p *fwProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}
