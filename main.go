package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	opts := providerserver.ServeOpts{
		Address: "local/fw-analyzer",
	}

	err := providerserver.Serve(context.Background(), NewProvider, opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
