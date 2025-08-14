/*
Copyright © 2025 Victor Hang vhvictorhang@gmail.com
*/
package main

import (
	"github.com/Banh-Canh/songbird/cmd"
	_ "github.com/Banh-Canh/songbird/cmd/dns"
	_ "github.com/Banh-Canh/songbird/cmd/netpol"
)

func main() {
	cmd.Execute()
}
