package main

import (
	"github.com/hashicorp/vault/plugins"
	atlas "github.com/mealal/vault-atlas-plugin"
)

func main() {
	plugins.Serve(new(atlas.Atlas), nil)
}
