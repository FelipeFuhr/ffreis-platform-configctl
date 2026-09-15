package main

import (
	"os"

	"github.com/FelipeFuhr/ffreis-platform-configctl/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
