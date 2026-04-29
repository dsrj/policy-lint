package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	err := providerserver.Serve(context.Background(), NewProvider, providerserver.ServeOpts{
		Address:         "registry.terraform.io/local/fw-analyzer",
		ProtocolVersion: 6,
	})

	if err != nil {
		log.Fatal(err)
	}
}