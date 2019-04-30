package main

import (
	"log"
	"os"

	api "github.com/hashicorp/vault/api"
	atlas "github.com/mealal/vault-atlas-plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := atlas.Run(apiClientMeta.GetTLSConfig())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
