/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	"github.com/Banh-Canh/songbird/internal/k8s/networkpolicy"
	"github.com/Banh-Canh/songbird/internal/utils/logger"
)

var outputFormat string

var showCmd = &cobra.Command{
	Use:   "show <namespace>/<podname>",
	Short: "Displays all NetworkPolicies that affect a specific pod",
	Long: `This command lists all NetworkPolicies from all namespaces that apply to a given pod.

It takes a single argument in the format 'namespace/podname'.

By default, it shows a table with the policy names. Use the -o or --output flag to output the full YAML of the policies.

Example:

songbird show my-namespace/my-app-pod
songbird show my-namespace/my-app-pod -o yaml
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Load kubeconfig
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			logger.Logger.Error("failed to load kubeconfig from environment variable", slog.Any("error", err))
			return
		}
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			logger.Logger.Error("failed to create k8s client", slog.Any("error", err))
			return
		}
		ctx := context.Background()

		// Parse the pod argument
		podInfo := strings.Split(args[0], "/")
		if len(podInfo) != 2 {
			logger.Logger.Error("invalid pod format. Must be 'namespace/podname'", slog.String("provided", args[0]))
			return
		}
		podNamespace := podInfo[0]
		podName := podInfo[1]

		// Get the specified pod
		pod, err := clientset.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			logger.Logger.Error(
				"failed to get pod",
				slog.String("pod_name", podName),
				slog.String("namespace", podNamespace),
				slog.Any("error", err),
			)
			return
		}

		// Get all NetworkPolicies from all namespaces
		npl, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Logger.Error("failed to list network policies", slog.Any("error", err))
			return
		}

		nps := make([]*networkingv1.NetworkPolicy, len(npl.Items))
		for i := range npl.Items {
			nps[i] = &npl.Items[i]
		}

		// Get the policies that apply directly to the pod
		localPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(pod, nps)
		if err != nil {
			logger.Logger.Error("failed to get local network policies for pod", slog.Any("error", err))
			return
		}

		// Check the output format flag
		if outputFormat == "yaml" {
			if len(localPolicies) == 0 {
				fmt.Println("No NetworkPolicies found for this pod.")
			} else {
				for _, np := range localPolicies {
					// Marshal each policy to YAML and print it with a separator
					yamlBytes, err := yaml.Marshal(np)
					if err != nil {
						logger.Logger.Error("failed to marshal NetworkPolicy to YAML", slog.Any("error", err))
						continue
					}
					fmt.Println("---")
					fmt.Println(string(yamlBytes))
				}
			}
			return
		} else if outputFormat != "" {
			logger.Logger.Error("invalid output format. Must be 'yaml'", slog.String("format", outputFormat))
			return
		}

		// Default table output
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(w, "NAMESPACE\tPOLICY_NAME"); err != nil {
			logger.Logger.Error("failed to write header to tabwriter", slog.Any("error", err))
			return
		}

		if len(localPolicies) == 0 {
			if _, err := fmt.Fprintln(w, fmt.Sprintf("%s\t(no policies found)", podNamespace)); err != nil {
				logger.Logger.Error("failed to write row to tabwriter", slog.Any("error", err))
			}
		} else {
			for _, np := range localPolicies {
				if _, err := fmt.Fprintf(w, "%s\t%s\n", np.Namespace, np.Name); err != nil {
					logger.Logger.Error("failed to write row to tabwriter", slog.Any("error", err))
					return
				}
			}
		}

		if err := w.Flush(); err != nil {
			logger.Logger.Error("failed to flush tabwriter", slog.Any("error", err))
		}
	},
}

func init() {
	RootCmd.AddCommand(showCmd)
	showCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format. Only 'yaml' is supported.")
}
