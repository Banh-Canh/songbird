/*
Copyright © 2025 Victor Hang <vhvictorhang@gmail.com>
*/
package netpol

import (
	"github.com/spf13/cobra"

	"github.com/Banh-Canh/songbird/cmd"
)

// netpolCmd represents the netpol command
var netpolCmd = &cobra.Command{
	Use:   "netpol",
	Short: "Troubleshoot Kubernetes Network Policies",
	Long: `A tool for diagnosing and validating network policies in Kubernetes.
Use the subcommands to check connectivity between pods, view active policies,
and get detailed information about how policies are affecting traffic.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help() //nolint:all
	},
}

func init() {
	cmd.RootCmd.AddCommand(netpolCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// netpolCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// netpolCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
