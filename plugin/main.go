// Copyright (c) chris moran
// SPDX-License-Identifier: MIT

package main

import (
	"log"
	"os"

	plugin "github.com/cmmoran/openbao-plugin-database-oracle"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	_ = flags.Parse(os.Args[1:])

	err := Run()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func Run() error {
	dbplugin.ServeMultiplex(plugin.New)

	return nil
}
