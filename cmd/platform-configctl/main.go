package main

import (
	"os"

	"github.com/ffreis/platform-configctl/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
