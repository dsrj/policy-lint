package main

import (
	"context"

	"://github.com"
	"://github.com"
	"://github.com"
)

type fwProvider struct{}

func NewProvider() provider.Provider {
	return &fwProvider{}
}

func (p *fwProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "fw_analyzer"
}

func (p *fwProvider) Schema(_ context.Context, _ provider.SchemaRequest, _ *provider.SchemaResponse) {}

func (p *fwProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {}

func (p *fwProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewAnalysisDataSource,
	}
}

func (p *fwProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}
