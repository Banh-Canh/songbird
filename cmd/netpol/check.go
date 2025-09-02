/*
Copyright © 2025 Victor Hang <vhvictorhang@gmail.com>
*/
package netpol

import (
	"context"
	"log/slog"
	"net"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Banh-Canh/songbird/internal/k8s/networkpolicy"
	"github.com/Banh-Canh/songbird/internal/utils/logger"
)

var (
	addressFlag    string
	portFlag       int
	namespaceFlag  string
	directionFlag  string
	outputFlag     string
	targetPodFlag  string
	deniedOnlyFlag bool
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Evaluate network policies configuration to check for connectivity",
	Long: `Evaluate network policies configuration to check for connectivity

It relies on ip and port input. The ip can be the ip of a pod.
It will automatically check for labels and selectors and verify that this ip is allowed in ingress or egress.

If no address or pod is specified, interactive mode will be started with fuzzy finder menus.
If an address is specified, you can interactively select the source namespace.

Examples:

# Specify target directly
songbird netpol check -a 10.1.0.225 -p 80 -d ingress -n my-namespace
songbird netpol check -P my-namespace/my-app-pod -p 80 -d ingress -n another-namespace

# Interactive source selection with target address
songbird netpol check -a 10.1.0.225 -p 80 -d all

# Full interactive mode (will show fuzzy finder menus for source and destination)
songbird netpol check -p 80 -d all
`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load kubeconfig
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			logger.Logger.Error("failed to load kubeconfig from environment variable", slog.Any("error", err))
			return
		}
		config.QPS = 100
		config.Burst = 100
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			logger.Logger.Error("failed to create k8s client", slog.Any("error", err))
			return
		}
		ctx := context.Background()

		// Validate port for direct mode
		if (addressFlag != "" || targetPodFlag != "") && portFlag == 0 {
			logger.Logger.Error("port must be specified (-p flag) when using direct IP or pod mode")
			return
		}

		var targetIP net.IP
		var sourceNamespace string

		if targetPodFlag != "" {
			parts := strings.Split(targetPodFlag, "/")
			if len(parts) != 2 {
				logger.Logger.Error("invalid pod format. Must be 'namespace/podname'", slog.String("provided", targetPodFlag))
				return
			}
			targetPodNamespace := parts[0]
			targetPodName := parts[1]

			targetPod, err := clientset.CoreV1().Pods(targetPodNamespace).Get(ctx, targetPodName, metav1.GetOptions{})
			if err != nil {
				logger.Logger.Error(
					"failed to get pod by name",
					slog.String("pod_name", targetPodName),
					slog.String("namespace", targetPodNamespace),
					slog.Any("error", err),
				)
				return
			}
			if targetPod.Status.PodIP == "" {
				logger.Logger.Error("pod does not have an IP address", slog.String("pod_name", targetPodName))
				return
			}
			targetIP = net.ParseIP(targetPod.Status.PodIP)
		} else if addressFlag != "" {
			targetIP = net.ParseIP(addressFlag)
			if targetIP == nil {
				logger.Logger.Error("invalid IP address", slog.String("addressIP", addressFlag))
				return
			}

			// When address is specified, allow interactive source selection
			selector := networkpolicy.NewInteractiveSelector(clientset, ctx)

			// Check permissions first
			if err := selector.CheckPermissions(); err != nil {
				logger.Logger.Error("permission check failed", slog.Any("error", err))
				return
			}

			// Select source namespace
			sourceNs, err := selector.SelectNamespaceWithPrompt("Source namespace > ")
			if err != nil {
				logger.Logger.Error("failed to select source namespace", slog.Any("error", err))
				return
			}
			sourceNamespace = sourceNs.Name

		} else {
			// No address or pod specified - start full interactive mode

			// Check if port is specified for interactive mode
			if portFlag == 0 {
				logger.Logger.Error("port must be specified (-p flag)")
				return
			}

			// Create interactive selector
			selector := networkpolicy.NewInteractiveSelector(clientset, ctx)

			// Run interactive network policy check
			if err := selector.InteractiveNetworkPolicyCheck(portFlag, directionFlag, outputFlag, deniedOnlyFlag); err != nil {
				logger.Logger.Error("interactive network policy check failed", slog.Any("error", err))
				return
			}
			return
		}

		// Use the selected source namespace if available, otherwise fall back to the namespace flag
		finalNamespace := namespaceFlag
		if sourceNamespace != "" {
			finalNamespace = sourceNamespace
		}

		// Call the reusable function with the parameters from the flags
		if err := networkpolicy.RunNetpolCheck(ctx, clientset, targetIP, portFlag, finalNamespace, directionFlag, outputFlag, deniedOnlyFlag); err != nil {
			logger.Logger.Error("network policy check failed", slog.Any("error", err))
			return
		}
	},
}

func init() {
	netpolCmd.AddCommand(checkCmd)
	checkCmd.Flags().StringVarP(&addressFlag, "address", "a", "", "the ip address to check")
	checkCmd.Flags().IntVarP(&portFlag, "port", "p", 0, "the port to check")
	checkCmd.Flags().StringVarP(&namespaceFlag, "namespace", "n", "", "the namespace to filter pods to check against")
	checkCmd.Flags().StringVarP(&directionFlag, "direction", "d", "all", "the traffic direction to check (ingress, egress, or all)")
	checkCmd.Flags().
		StringVarP(&outputFlag, "output", "o", "", "Output format. Use 'wide' for additional information or 'json' for JSON output.")
	checkCmd.Flags().StringVarP(&targetPodFlag, "pod", "P", "", "the pod to check, in the format 'namespace/podname'")
	checkCmd.Flags().BoolVarP(&deniedOnlyFlag, "denied-only", "", false, "only display denied traffic")

	checkCmd.MarkFlagsMutuallyExclusive("address", "pod")
	// Port is required when using direct IP/pod mode, but will be validated at runtime
}
