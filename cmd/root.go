/*
Copyright © 2025 Victor Hang vhvictorhang@gmail.com
*/
package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/Banh-Canh/songbird/internal/utils/logger"
)

var (
	versionFlag  bool
	logLevelFlag string
	version      string
)

// rootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "songbird",
	Short: "A brief description of your application",
	Long: `Evaluate network policies configuration to check for connectivity
`,

	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag {
			fmt.Printf("%s", version)
			os.Exit(0)
		}
	},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize configuration here
		initConfig()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		logger.Logger.Error("error", slog.Any("error", err))
	}
}

func initConfig() {
	logLevel := slog.LevelInfo
	if logLevelFlag == "debug" {
		logLevel = slog.LevelDebug
	}
	logger.InitializeLogger(logLevel)
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.songbird.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	RootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "display version information")
	RootCmd.PersistentFlags().StringVarP(&logLevelFlag, "log-level", "l", "", "Override log level (debug, info)")
}
