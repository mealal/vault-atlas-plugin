package main

import (
	"log"
	"os"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/mealal/vault-atlas-plugin"
)

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := atlas.Run(apiClientMeta.GetTLSConfig())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}