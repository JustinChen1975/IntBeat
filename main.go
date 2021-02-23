package main

import (
	"os"

	"github.com/JustinChen1975/intbeat/cmd"

	_ "github.com/JustinChen1975/intbeat/include"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
