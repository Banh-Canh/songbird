/*
Copyright © 2025 Victor Hang <vhvictorhang@gmail.com>
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
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
	outputFlag    string
	targetPodFlag string
)

// CheckResult defines the structure for the JSON output.
type CheckResult struct {
	Namespace       string   `json:"namespace"`
	Pod             string   `json:"pod"`
	Direction       string   `json:"direction"`
	Target          string   `json:"target,omitempty"`
	Port            int      `json:"port,omitempty"`
	NetworkPolicies []string `json:"networkPolicies,omitempty"`
	Status          string   `json:"status"`
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "evaluate network policies configuration to check for connectivity",
	Long: `Evaluate network policies configuration to check for connectivity

It relies on ip and port input. The ip can be the ip of a pod.
It will automatically check for labels and selectors and verify that this ip is allowed in ingress or egress.

Example:

songbird check -a 10.1.0.225 -p 40 -d ingress -n my-namespace

songbird check -P my-namespace/my-app-pod -p 80 -d ingress -n another-namespace
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
		config.QPS = 100
		config.Burst = 100
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			logger.Logger.Error("failed to create k8s client", slog.Any("error", err))
			return
		}
		ctx := context.Background()

		var targetIP net.IP
		var targetPod *v1.Pod
		var targetPodNamespace string

		if targetPodFlag != "" {
			parts := strings.Split(targetPodFlag, "/")
			if len(parts) != 2 {
				logger.Logger.Error("invalid pod format. Must be 'namespace/podname'", slog.String("provided", targetPodFlag))
				return
			}
			targetPodNamespace = parts[0]
			targetPodName := parts[1]

			targetPod, err = clientset.CoreV1().Pods(targetPodNamespace).Get(ctx, targetPodName, metav1.GetOptions{})
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
		} else {
			logger.Logger.Error("either an IP address or a pod name must be provided")
			return
		}

		// Pre-fetch all necessary resources to avoid repeated API calls.
		allPods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Logger.Error("failed to list all pods", slog.Any("error", err))
			return
		}
		allNamespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Logger.Error("failed to list all namespaces", slog.Any("error", err))
			return
		}
		npl, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Logger.Error("failed to list network policies", slog.Any("error", err))
			return
		}

		nps := make([]*networkingv1.NetworkPolicy, len(npl.Items))
		for i := range npl.Items {
			nps[i] = &npl.Items[i]
		}
		podsByIP := make(map[string]*v1.Pod)
		for i := range allPods.Items {
			p := &allPods.Items[i]
			if p.Status.PodIP != "" {
				podsByIP[p.Status.PodIP] = p
			}
		}
		namespacesByName := make(map[string]*v1.Namespace)
		for i := range allNamespaces.Items {
			ns := &allNamespaces.Items[i]
			namespacesByName[ns.Name] = ns
		}

		var podsToCheck *v1.PodList
		if namespaceFlag != "" {
			// Filter pods based on the provided namespace flag
			filteredPods := []v1.Pod{}
			for _, pod := range allPods.Items {
				if pod.Namespace == namespaceFlag {
					filteredPods = append(filteredPods, pod)
				}
			}
			podsToCheck = &v1.PodList{Items: filteredPods}
		} else {
			podsToCheck = allPods
		}

		logger.Logger.Debug("successfully listed pods", slog.Int("pod_count", len(podsToCheck.Items)))
		logger.Logger.Debug("successfully listed network policies", slog.Int("network_policy_count", len(nps)))

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

		// Initialize JSON output
		var results []CheckResult
		isJSON := outputFlag == "json"
		isWide := outputFlag == "wide"

		// Set up tabwriter for non-JSON output
		var w *tabwriter.Writer
		if !isJSON {
			w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			if isWide {
				if _, err := fmt.Fprintln(w, "NAMESPACE\tPOD\tDIRECTION\tTARGET\tPORT\tNETWORK_POLICIES\tSTATUS"); err != nil {
					logger.Logger.Error("failed to write wide header to tabwriter", slog.Any("error", err))
					return
				}
			} else {
				if _, err := fmt.Fprintln(w, "NAMESPACE\tPOD\tDIRECTION\tSTATUS"); err != nil {
					logger.Logger.Error("failed to write header to tabwriter", slog.Any("error", err))
					return
				}
			}
		}

		// 3. Check each pod in the filtered list
		for _, pod := range podsToCheck.Items {
			if pod.Status.PodIP == "" {
				logger.Logger.Info(
					"skipping pod with no IP address",
					slog.String("pod_name", pod.Name),
					slog.String("namespace", pod.Namespace),
				)
				continue
			}
			srcPod := &pod

			localPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(srcPod, nps)
			if err != nil {
				logger.Logger.Error("failed to get local network policies for pod", slog.Any("error", err))
				return
			}

			allAffectingPolicies, err := networkpolicy.GetAllAffectingNetworkPolicies(allPods, allNamespaces, srcPod, nps)
			if err != nil {
				logger.Logger.Error("failed to get all affecting network policies for pod", slog.Any("error", err))
				return
			}

			var policyNames []string
			for _, np := range allAffectingPolicies {
				policyNames = append(policyNames, fmt.Sprintf("%s/%s", np.Namespace, np.Name))
			}
			matchedPolicies := strings.Join(policyNames, ", ")
			if matchedPolicies == "" {
				matchedPolicies = "none"
			}

			for _, policyType := range policyTypes {
				var directionText string
				if policyType == networkingv1.PolicyTypeEgress {
					directionText = "egress"
				} else {
					directionText = "ingress"
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
					localPolicies,
					policyType,
					srcPod,
					targetIP,
					portFlag,
					podsByIP,
					namespacesByName,
				)
				if err != nil {
					logger.Logger.Error("failed to evaluate pod connectivity", slog.Any("error", err))
					return
				}

				status := "DENIED ❌"
				if allowed {
					status = "ALLOWED ✅"
				}

				// Create result for JSON output
				result := CheckResult{
					Namespace: srcPod.Namespace,
					Pod:       srcPod.Name,
					Direction: directionText,
					Status:    status,
				}

				// Add wide information if needed
				if isWide || isJSON {
					result.Target = targetIP.String()
					result.Port = portFlag
					result.NetworkPolicies = policyNames
				}
				results = append(results, result)

				// Output to tabwriter if not JSON
				if !isJSON {
					if isWide {
						if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", srcPod.Namespace, srcPod.Name, directionText, targetIP.String(), portFlag, matchedPolicies, status); err != nil {
							logger.Logger.Error("failed to write wide row to tabwriter", slog.Any("error", err))
							return
						}
					} else {
						if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", srcPod.Namespace, srcPod.Name, directionText, status); err != nil {
							logger.Logger.Error("failed to write row to tabwriter", slog.Any("error", err))
							return
						}
					}
				}
			}
		}

		if isJSON {
			// Marshal results slice into JSON with indentation
			output, err := json.MarshalIndent(results, "", "  ")
			if err != nil {
				logger.Logger.Error("failed to marshal results to JSON", slog.Any("error", err))
				return
			}
			fmt.Println(string(output))
		} else {
			if err := w.Flush(); err != nil {
				logger.Logger.Error("failed to flush tabwriter", slog.Any("error", err))
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(checkCmd)
	checkCmd.Flags().StringVarP(&addressFlag, "address", "a", "", "the ip address to check")
	checkCmd.Flags().IntVarP(&portFlag, "port", "p", 0, "the port to check")
	checkCmd.Flags().StringVarP(&namespaceFlag, "namespace", "n", "", "the namespace to filter pods to check against")
	checkCmd.Flags().StringVarP(&directionFlag, "direction", "d", "all", "the traffic direction to check (ingress, egress, or all)")
	checkCmd.Flags().
		StringVarP(&outputFlag, "output", "o", "", "Output format. Use 'wide' for additional information or 'json' for JSON output.")
	checkCmd.Flags().StringVarP(&targetPodFlag, "pod", "P", "", "the pod to check, in the format 'namespace/podname'")

	checkCmd.MarkFlagsMutuallyExclusive("address", "pod")
	checkCmd.MarkFlagRequired("port") //nolint:all
}
