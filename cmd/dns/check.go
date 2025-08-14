package dns

import (
	"context"
	"log/slog"
	"net"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Banh-Canh/songbird/internal/k8s/networkpolicy"
	"github.com/Banh-Canh/songbird/internal/utils/logger"
)

var (
	namespaceFlag string
	outputFlag    string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check connectivity to the CoreDNS pod on port 53",
	Long: `This subcommand automatically finds the CoreDNS pod and checks for connectivity to it on port 53.
It simplifies the process of verifying DNS resolution policies within the cluster.`,
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

		// Find the CoreDNS pod's IP.
		// CoreDNS pods are typically in the 'kube-system' namespace with the label 'k8s-app=kube-dns'.
		corednsPods, err := clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=kube-dns",
		})
		if err != nil || len(corednsPods.Items) == 0 {
			logger.Logger.Error("failed to find CoreDNS pod in kube-system namespace", slog.Any("error", err))
			return
		}

		corednsPod := &corednsPods.Items[0]
		if corednsPod.Status.PodIP == "" {
			logger.Logger.Error("CoreDNS pod does not have an IP address")
			return
		}
		targetIP := net.ParseIP(corednsPod.Status.PodIP)

		// Call the reusable `runNetpolCheck` function with the determined values.
		err = networkpolicy.RunNetpolCheck(ctx, clientset, targetIP, 53, namespaceFlag, "egress", outputFlag, true)
		if err != nil {
			logger.Logger.Error("network policy check failed", slog.Any("error", err))
			return
		}
	},
}

func init() {
	dnsCmd.AddCommand(checkCmd)
	checkCmd.Flags().StringVarP(&namespaceFlag, "namespace", "n", "", "the namespace to filter pods to check against")
	checkCmd.Flags().
		StringVarP(&outputFlag, "output", "o", "", "Output format. Use 'wide' for additional information or 'json' for JSON output.")
}
