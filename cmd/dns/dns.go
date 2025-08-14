/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package dns

import (
	"github.com/spf13/cobra"

	"github.com/Banh-Canh/songbird/cmd"
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Troubleshoot and query DNS records",
	Long: `A tool for diagnosing DNS resolution issues and inspecting
DNS records. It can perform various types of lookups to help you verify that your services are correctly configured.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help() //nolint:all
	},
}

func init() {
	cmd.RootCmd.AddCommand(dnsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dnsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dnsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
