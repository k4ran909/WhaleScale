// Command terraform-provider-whalescale manages a Whalescale network from
// Terraform or OpenTofu: the access policy, users, pre-auth keys and route
// approvals, through the admin API.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/k4ran909/whalescale/terraform/internal/provider"
)

var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers like delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/k4ran909/whalescale",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
