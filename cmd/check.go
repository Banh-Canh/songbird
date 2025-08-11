/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Banh-Canh/songbird/internal/k8s/networkpolicy"
	"github.com/Banh-Canh/songbird/internal/utils/logger"
)

var (
	addressFlag   string
	portFlag      int
	namespaceFlag string
	directionFlag string
)

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "evaluate network policies configuration to check for connectivity",
	Long: `Evaluate network policies configuration to check for connectivity

It relies on ip and port input. The ip can be the ip of a pod.
It will automatically check for labels and selectors and verify that this ip is allowed in ingress or egress.

Example:

songbird check -a 10.1.0.225 -p 40 -d ingress
`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load kubeconfig
		// Create a new set of loading rules, which will check the KUBECONFIG env var
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

		// 1. Get all pods
		var (
			pods *v1.PodList
		)
		if namespaceFlag != "" {
			pods, err = clientset.CoreV1().Pods(namespaceFlag).List(ctx, metav1.ListOptions{})
		} else {
			pods, err = clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		}
		if err != nil {
			logger.Logger.Error("failed to list pods", slog.Any("error", err))
			return
		}
		logger.Logger.Debug("successfully listed pods", slog.Int("pod_count", len(pods.Items)))

		// 2. Get all network policies
		npl, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Logger.Error("failed to list network policies", slog.Any("error", err))
			return
		}
		logger.Logger.Debug("successfully listed network policies", slog.Int("network_policy_count", len(npl.Items)))

		nps := make([]*networkingv1.NetworkPolicy, len(npl.Items))
		for i := range npl.Items {
			nps[i] = &npl.Items[i]
		}

		targetIP := net.ParseIP(addressFlag)
		if targetIP == nil {
			logger.Logger.Error("invalid IP address", slog.String("addressIP", addressFlag))
			return
		}

		var policyTypes []networkingv1.PolicyType
		switch directionFlag {
		case "egress":
			policyTypes = append(policyTypes, networkingv1.PolicyTypeEgress)
		case "ingress":
			policyTypes = append(policyTypes, networkingv1.PolicyTypeIngress)
		case "all":
			policyTypes = append(policyTypes, networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress)
		default:
			logger.Logger.Error("invalid direction flag. Must be 'ingress', 'egress', or 'all'", slog.String("direction", directionFlag))
			return
		}
		// 3. Check each pod
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		// Write to tabwrite for later output
		if _, err := fmt.Fprintln(w, "NAMESPACE\tPOD\tDIRECTION\tTARGET\tPORT\tSTATUS"); err != nil {
			logger.Logger.Error("failed to write header to tabwriter", slog.Any("error", err))
			return
		}
		for _, pod := range pods.Items {
			if pod.Status.PodIP == "" {
				logger.Logger.Info(
					"skipping pod with no IP address",
					slog.String("pod_name", pod.Name),
					slog.String("namespace", pod.Namespace),
				)
				continue
			}
			srcPod := &pod
			srcPodNetworkPolicies, err := networkpolicy.GetNetworkPoliciesForPod(pod, nps)
			if err != nil {
				logger.Logger.Error("failed to get network policies for pod", slog.Any("error", err))
				return
			}
			for _, policyType := range policyTypes {
				var directionText string
				if policyType == networkingv1.PolicyTypeEgress {
					directionText = "to"
				} else {
					directionText = "from"
				}

				logger.Logger.Debug(
					fmt.Sprintf(
						"Checking %s for pod '%s' %s IP '%s' on port '%d'",
						policyType,
						srcPod.Name,
						directionText,
						targetIP.String(),
						portFlag,
					),
					slog.String("policy_type", string(policyType)),
					slog.String("pod_name", srcPod.Name),
					slog.String("direction", directionText),
					slog.String("target_ip", targetIP.String()),
					slog.Int("port", portFlag),
				)
				allowed, err := networkpolicy.EvaluatePodConnectivity(
					clientset,
					srcPodNetworkPolicies,
					policyType,
					srcPod,
					targetIP,
					portFlag,
				)
				if err != nil {
					logger.Logger.Error("failed to evaluate pod connectivity", slog.Any("error", err))
					return
				}

				status := "DENIED ❌"
				if allowed {
					status = "ALLOWED ✅"
				}
				if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n", srcPod.Namespace, srcPod.Name, directionText, targetIP.String(), portFlag, status); err != nil {
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
	RootCmd.AddCommand(checkCmd)
	checkCmd.Flags().StringVarP(&addressFlag, "address", "a", "", "the ip address to check")
	checkCmd.Flags().IntVarP(&portFlag, "port", "p", 0, "the port to check")
	checkCmd.Flags().StringVarP(&namespaceFlag, "namespace", "n", "", "the namespace to check")
	checkCmd.Flags().StringVarP(&directionFlag, "direction", "d", "all", "the traffic direction to check (ingress, egress, or all)")
	checkCmd.MarkFlagRequired("address") //nolint:all
	checkCmd.MarkFlagRequired("port")    //nolint:all
}
