package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	"github.com/Banh-Canh/songbird/internal/utils/logger"
)

var createCmd = &cobra.Command{
	Use:   "create [target-namespace/target-pod]",
	Short: "generate a network policy yaml to allow connectivity to a pod",
	Long: `Generate a Kubernetes NetworkPolicy YAML based on a target pod or an IP address.

This command inspects the labels of the specified pods or uses a provided IP to create a specific
NetworkPolicy that allows traffic on a given port and direction.

Examples:

# Create a policy in the 'my-app' namespace, allowing ingress from 'my-db/db-pod' to 'my-app/api-pod' on port 5432
songbird create my-app/api-pod -P my-db/db-pod -d ingress -p 5432

# Create a policy allowing ingress from a specific IP address to 'my-app/api-pod'
songbird create my-app/api-pod -a 192.168.1.10/32 -d ingress -p 8080
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

		// Validate that either a peer pod or an address is provided, but not both
		if targetPodFlag != "" && addressFlag != "" {
			logger.Logger.Error("cannot specify both a peer pod and an IP address. Use either -P or -a.")
			return
		}
		if targetPodFlag == "" && addressFlag == "" {
			logger.Logger.Error("must provide a peer pod or an IP address with --peer-pod/-P or --address/-a")
			return
		}
		// Parse the target pod argument
		targetPodParts := strings.Split(args[0], "/")
		if len(targetPodParts) != 2 {
			logger.Logger.Error("invalid target pod format. Must be 'namespace/podname'", slog.String("provided", args[0]))
			return
		}
		targetPodNamespace := targetPodParts[0]
		targetPodName := targetPodParts[1]

		// Get the target pod and its labels
		targetPod, err := clientset.CoreV1().Pods(targetPodNamespace).Get(ctx, targetPodName, metav1.GetOptions{})
		if err != nil {
			logger.Logger.Error("failed to get target pod", slog.String("pod", args[0]), slog.Any("error", err))
			return
		}

		// Filter generated labels to target the workload, not a specific pod instance
		filteredTargetLabels := filterGeneratedLabels(targetPod.Labels)
		if len(filteredTargetLabels) == 0 {
			logger.Logger.Error("target pod has no non-generated labels. Cannot create a surgical policy.", slog.String("pod", args[0]))
			return
		}

		// Prepare the NetworkPolicy
		policyName := fmt.Sprintf("allow-%s-to-access-on-%d", targetPodName, portFlag)
		policy := &networkingv1.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "networking.k8s.io/v1",
				Kind:       "NetworkPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      policyName,
				Namespace: targetPodNamespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: filteredTargetLabels,
				},
			},
		}

		port := intstr.FromInt(portFlag)
		policyPeer := networkingv1.NetworkPolicyPeer{}

		// Handle peer based on the flag provided
		if targetPodFlag != "" {
			peerPodParts := strings.Split(targetPodFlag, "/")
			if len(peerPodParts) != 2 {
				logger.Logger.Error("invalid peer pod format. Must be 'namespace/podname'", slog.String("provided", targetPodFlag))
				return
			}
			peerPodNamespace := peerPodParts[0]
			peerPodName := peerPodParts[1]

			// Get the peer pod and its labels
			peerPod, err := clientset.CoreV1().Pods(peerPodNamespace).Get(ctx, peerPodName, metav1.GetOptions{})
			if err != nil {
				logger.Logger.Error("failed to get peer pod", slog.String("pod", targetPodFlag), slog.Any("error", err))
				return
			}

			filteredPeerLabels := filterGeneratedLabels(peerPod.Labels)
			if len(filteredPeerLabels) == 0 {
				logger.Logger.Error(
					"peer pod has no non-generated labels. Cannot create a surgical policy.",
					slog.String("pod", targetPodFlag),
				)
				return
			}

			policyPeer.PodSelector = &metav1.LabelSelector{
				MatchLabels: filteredPeerLabels,
			}

			// Check if the pods are in different namespaces, and add a NamespaceSelector if needed
			if targetPodNamespace != peerPodNamespace {
				policyPeer.NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/metadata.name": peerPodNamespace,
					},
				}
			}

			policyName = fmt.Sprintf("allow-%s-%s-on-%d", targetPodName, peerPodName, portFlag)
		} else if addressFlag != "" {
			// Validate that the provided address is a valid CIDR block
			if _, _, err := net.ParseCIDR(addressFlag); err != nil {
				logger.Logger.Error("invalid CIDR block provided with --address", slog.String("address", addressFlag), slog.Any("error", err))
				return
			}
			policyPeer.IPBlock = &networkingv1.IPBlock{
				CIDR: addressFlag,
			}
			policyName = fmt.Sprintf("allow-%s-from-ip-on-%d", targetPodName, portFlag)
		}

		// Set policy types and rules based on the direction flag
		switch directionFlag {
		case "ingress":
			policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{
				{
					From:  []networkingv1.NetworkPolicyPeer{policyPeer},
					Ports: []networkingv1.NetworkPolicyPort{{Port: &port}},
				},
			}
		case "egress":
			policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{
					To:    []networkingv1.NetworkPolicyPeer{policyPeer},
					Ports: []networkingv1.NetworkPolicyPort{{Port: &port}},
				},
			}
		case "all":
			policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{
				{
					From:  []networkingv1.NetworkPolicyPeer{policyPeer},
					Ports: []networkingv1.NetworkPolicyPort{{Port: &port}},
				},
			}
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{
					To:    []networkingv1.NetworkPolicyPeer{policyPeer},
					Ports: []networkingv1.NetworkPolicyPort{{Port: &port}},
				},
			}
		default:
			logger.Logger.Error("invalid direction flag. Must be 'ingress', 'egress', or 'all'", slog.String("direction", directionFlag))
			return
		}

		policy.Name = policyName
		// Marshal the policy to YAML and print
		yamlBytes, err := yaml.Marshal(policy)
		if err != nil {
			logger.Logger.Error("failed to marshal network policy to YAML", slog.Any("error", err))
			return
		}
		if _, err = os.Stdout.Write(yamlBytes); err != nil {
			logger.Logger.Error("failed to write YAML to stdout", slog.Any("error", err))
			return
		}
	},
}

// filterGeneratedLabels removes labels that are typically generated by Kubernetes controllers,
// such as "pod-template-hash," to ensure the NetworkPolicy targets the workload and not a specific pod instance.
func filterGeneratedLabels(labels map[string]string) map[string]string {
	filtered := make(map[string]string)
	for k, v := range labels {
		// Exclude labels known to be generated by Kubernetes controllers
		if k == "pod-template-hash" {
			continue
		}
		filtered[k] = v
	}
	return filtered
}

func init() {
	RootCmd.AddCommand(createCmd)
	createCmd.Flags().
		StringVarP(&targetPodFlag, "peer-pod", "P", "", "the pod to allow connectivity from, in the format 'namespace/podname'")
	createCmd.Flags().
		StringVarP(&addressFlag, "address", "a", "", "the IP address or CIDR block to allow connectivity from (e.g., 192.168.1.10/32)")
	createCmd.Flags().IntVarP(&portFlag, "port", "p", 0, "the port to allow")
	createCmd.Flags().StringVarP(&directionFlag, "direction", "d", "all", "the traffic direction to check (ingress, egress, or all)")
	createCmd.MarkFlagRequired("port") //nolint:all
}
