package networkpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/Banh-Canh/songbird/internal/utils/logger"
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

// RunNetpolCheck contains the core logic for evaluating network policies.
// It is a reusable function that doesn't depend on global flags.
func RunNetpolCheck(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	targetIP net.IP,
	port int,
	namespace string,
	direction string,
	output string,
	showDeniedOnly bool, // New flag added here
) error {
	// Pre-fetch all necessary resources to avoid repeated API calls.
	allPods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list all pods: %w", err)
	}
	allNamespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list all namespaces: %w", err)
	}
	npl, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list network policies: %w", err)
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
	if namespace != "" {
		filteredPods := []v1.Pod{}
		for _, pod := range allPods.Items {
			if pod.Namespace == namespace {
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
	switch direction {
	case "egress":
		policyTypes = append(policyTypes, networkingv1.PolicyTypeEgress)
	case "ingress":
		policyTypes = append(policyTypes, networkingv1.PolicyTypeIngress)
	case "all":
		policyTypes = append(policyTypes, networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress)
	default:
		return fmt.Errorf("invalid direction: must be 'ingress', 'egress', or 'all'")
	}

	var results []CheckResult
	isJSON := output == "json"
	isWide := output == "wide"

	var w *tabwriter.Writer
	if !isJSON {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if isWide {
			if _, err := fmt.Fprintln(w, "NAMESPACE\tPOD\tDIRECTION\tTARGET\tPORT\tNETWORK_POLICIES\tSTATUS"); err != nil {
				return fmt.Errorf("failed to write wide header to tabwriter: %w", err)
			}
		} else {
			if _, err := fmt.Fprintln(w, "NAMESPACE\tPOD\tDIRECTION\tTARGET\tPORT\tSTATUS"); err != nil {
				return fmt.Errorf("failed to write header to tabwriter: %w", err)
			}
		}
	}

	var targetIdentifier string
	if p, ok := podsByIP[targetIP.String()]; ok {
		targetIdentifier = fmt.Sprintf("%s/%s", p.Namespace, p.Name)
	} else {
		targetIdentifier = targetIP.String()
	}

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

		localPolicies, err := GetLocalNetworkPoliciesForPod(srcPod, nps)
		if err != nil {
			return fmt.Errorf("failed to get local network policies for pod: %w", err)
		}
		allAffectingPolicies, err := GetAllAffectingNetworkPolicies(allPods, allNamespaces, srcPod, nps)
		if err != nil {
			return fmt.Errorf("failed to get all affecting network policies for pod: %w", err)
		}

		var policyNames []string
		for _, np := range allAffectingPolicies {
			policyNames = append(policyNames, fmt.Sprintf("%s/%s", np.Namespace, np.Name))
		}
		matchedPolicies := strings.Join(policyNames, ", ")
		if matchedPolicies == "" {
			matchedPolicies = "none"
		}

		// Find the destination pod if the target IP belongs to one
		var peerPod *v1.Pod
		if p, ok := podsByIP[targetIP.String()]; ok {
			peerPod = p
		}

		for _, policyType := range policyTypes {
			var directionText string
			if policyType == networkingv1.PolicyTypeEgress {
				directionText = "to"
			} else {
				directionText = "from"
			}

			logger.Logger.Debug(
				"Checking network policy",
				slog.String("policy_type", string(policyType)),
				slog.String("pod_name", srcPod.Name),
				slog.String("direction", directionText),
				slog.String("target_ip", targetIP.String()),
				slog.Int("port", port),
			)

			var allowed bool
			var evalErr error

			switch policyType {
			case networkingv1.PolicyTypeEgress:
				// Evaluate egress from the source pod
				allowed, evalErr = EvaluatePodConnectivity(
					localPolicies,
					networkingv1.PolicyTypeEgress,
					srcPod,
					targetIP,
					port,
					podsByIP,
					namespacesByName,
				)

				// If a peer pod exists, also check its ingress rules
				if peerPod != nil && evalErr == nil {
					peerPolicies, getPeerPoliciesErr := GetLocalNetworkPoliciesForPod(peerPod, nps)
					if getPeerPoliciesErr != nil {
						evalErr = fmt.Errorf("failed to get policies for peer pod %s: %w", peerPod.Name, getPeerPoliciesErr)
					}

					// The 'peer' for the ingress check is the source pod's IP
					if evalErr == nil {
						allowedIngress, evalIngressErr := EvaluatePodConnectivity(
							peerPolicies,
							networkingv1.PolicyTypeIngress,
							peerPod,
							net.ParseIP(srcPod.Status.PodIP),
							port,
							podsByIP,
							namespacesByName,
						)
						if evalIngressErr != nil {
							evalErr = fmt.Errorf(
								"failed to evaluate ingress connectivity for peer pod %s: %w",
								peerPod.Name,
								evalIngressErr,
							)
						}
						// Final result is the logical AND of both checks
						allowed = allowed && allowedIngress
					}
				}
			case networkingv1.PolicyTypeIngress:
				// Evaluate ingress to the source pod
				allowed, evalErr = EvaluatePodConnectivity(
					localPolicies,
					networkingv1.PolicyTypeIngress,
					srcPod,
					targetIP, // Ingress peer is the target
					port,
					podsByIP,
					namespacesByName,
				)

				// If a peer pod exists, also check its egress rules
				if peerPod != nil && evalErr == nil {
					peerPolicies, getPeerPoliciesErr := GetLocalNetworkPoliciesForPod(peerPod, nps)
					if getPeerPoliciesErr != nil {
						evalErr = fmt.Errorf("failed to get policies for peer pod %s: %w", peerPod.Name, getPeerPoliciesErr)
					}

					// The 'peer' for the egress check is the source pod's IP
					if evalErr == nil {
						allowedEgress, evalEgressErr := EvaluatePodConnectivity(
							peerPolicies,
							networkingv1.PolicyTypeEgress,
							peerPod,
							net.ParseIP(srcPod.Status.PodIP),
							port,
							podsByIP,
							namespacesByName,
						)
						if evalEgressErr != nil {
							evalErr = fmt.Errorf("failed to evaluate egress connectivity for peer pod %s: %w", peerPod.Name, evalEgressErr)
						}
						// Final result is the logical AND of both checks
						allowed = allowed && allowedEgress
					}
				}
			}

			if evalErr != nil {
				return evalErr
			}

			status := "DENIED ❌"
			if allowed {
				status = "ALLOWED ✅"
			}

			// Check the new flag before proceeding
			if showDeniedOnly && allowed {
				continue // Skip to the next iteration if the connection is allowed
			}

			result := CheckResult{
				Namespace: srcPod.Namespace,
				Pod:       srcPod.Name,
				Direction: directionText,
				Status:    status,
			}
			if isWide || isJSON {
				result.Target = targetIdentifier
				result.Port = port
				result.NetworkPolicies = policyNames
			}
			results = append(results, result)

			if !isJSON {
				if isWide {
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", srcPod.Namespace, srcPod.Name, directionText, targetIdentifier, port, matchedPolicies, status); err != nil {
						return fmt.Errorf("failed to write wide row to tabwriter: %w", err)
					}
				} else {
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n", srcPod.Namespace, srcPod.Name, directionText, targetIdentifier, port, status); err != nil {
						return fmt.Errorf("failed to write row to tabwriter: %w", err)
					}
				}
			}
		}
	}

	if isJSON {
		outputJSON, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results to JSON: %w", err)
		}
		fmt.Println(string(outputJSON))
	} else {
		if err := w.Flush(); err != nil {
			return fmt.Errorf("failed to flush tabwriter: %w", err)
		}
	}

	return nil
}

func GetLocalNetworkPoliciesForPod(pod *v1.Pod, allNetworkPolicies []*networkingv1.NetworkPolicy) ([]*networkingv1.NetworkPolicy, error) {
	var policiesForPod []*networkingv1.NetworkPolicy
	podLabels := labels.Set(pod.Labels)

	for _, np := range allNetworkPolicies {
		if np.Namespace == pod.Namespace {
			selector, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
			if err != nil {
				return nil, fmt.Errorf("error parsing pod selector for network policy %s/%s: %w", np.Namespace, np.Name, err)
			}
			if selector.Matches(podLabels) {
				policiesForPod = append(policiesForPod, np)
			}
		}
	}
	return policiesForPod, nil
}

// GetAllAffectingNetworkPolicies returns all policies (local and remote namespace) that affect a given pod.
func GetAllAffectingNetworkPolicies(
	allPods *v1.PodList,
	allNamespaces *v1.NamespaceList,
	pod *v1.Pod,
	allNetworkPolicies []*networkingv1.NetworkPolicy,
) ([]*networkingv1.NetworkPolicy, error) {
	var policiesForPod []*networkingv1.NetworkPolicy

	// First, get the local policies that directly apply to the pod
	localPolicies, err := GetLocalNetworkPoliciesForPod(pod, allNetworkPolicies)
	if err != nil {
		return nil, err
	}
	policiesForPod = append(policiesForPod, localPolicies...)

	// Then, find policies in other namespaces that have rules affecting this pod
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

	for _, np := range allNetworkPolicies {
		if np.Namespace == pod.Namespace {
			continue
		}

		if doesPolicyTargetPod(namespacesByName, np, pod) {
			policiesForPod = append(policiesForPod, np)
		}
	}

	return policiesForPod, nil
}

// doesPolicyTargetPod checks if a network policy's ingress or egress rules
// target the given pod by using pre-computed maps for faster lookups.
func doesPolicyTargetPod(
	namespacesByName map[string]*v1.Namespace,
	np *networkingv1.NetworkPolicy,
	pod *v1.Pod,
) bool {
	// Check Ingress rules for a "from" peer that matches the pod's namespace/labels.
	for _, ingressRule := range np.Spec.Ingress {
		for _, peer := range ingressRule.From {
			if peer.NamespaceSelector != nil {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err == nil {
					if nsSelector.Matches(labels.Set(namespacesByName[pod.Namespace].Labels)) {
						if peer.PodSelector != nil {
							podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
							if err == nil && podSelector.Matches(labels.Set(pod.Labels)) {
								return true
							}
						} else {
							return true
						}
					}
				}
			}
		}
	}

	// Check Egress rules for a "to" peer that matches the pod's namespace/labels.
	for _, egressRule := range np.Spec.Egress {
		for _, peer := range egressRule.To {
			if peer.NamespaceSelector != nil {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err == nil {
					if nsSelector.Matches(labels.Set(namespacesByName[pod.Namespace].Labels)) {
						if peer.PodSelector != nil {
							podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
							if err == nil && podSelector.Matches(labels.Set(pod.Labels)) {
								return true
							}
						} else {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// EvaluatePodConnectivity checks if a pod connection is allowed based on a set of network policies.
func EvaluatePodConnectivity(
	networkPolicies []*networkingv1.NetworkPolicy,
	policyType networkingv1.PolicyType,
	targetPod *v1.Pod,
	peerIP net.IP,
	port int,
	podsByIP map[string]*v1.Pod,
	namespacesByName map[string]*v1.Namespace,
) (bool, error) {
	var appliesToPolicyType bool
	for _, netpol := range networkPolicies {
		if slices.Contains(netpol.Spec.PolicyTypes, policyType) {
			appliesToPolicyType = true
			break
		}
	}
	if !appliesToPolicyType {
		return true, nil
	}

	for _, netpol := range networkPolicies {
		if !slices.Contains(netpol.Spec.PolicyTypes, policyType) {
			continue
		}

		if policyType == networkingv1.PolicyTypeEgress {
			if len(netpol.Spec.Egress) == 0 {
				continue
			}
			for _, egressRule := range netpol.Spec.Egress {
				allowed, err := evaluateEgressRule(egressRule, peerIP, port, podsByIP, namespacesByName)
				if err != nil {
					return false, fmt.Errorf("error evaluating egress rule for policy %s: %w", netpol.Name, err)
				}
				if allowed {
					return true, nil
				}
			}
		} else if policyType == networkingv1.PolicyTypeIngress {
			if len(netpol.Spec.Ingress) == 0 {
				continue
			}
			for _, ingressRule := range netpol.Spec.Ingress {
				allowed, err := evaluateIngressRule(ingressRule, peerIP, port, podsByIP, namespacesByName)
				if err != nil {
					return false, fmt.Errorf("error evaluating ingress rule for policy %s: %w", netpol.Name, err)
				}
				if allowed {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// evaluateEgressRule checks if an egress rule allows a connection.
func evaluateEgressRule(
	egressRule networkingv1.NetworkPolicyEgressRule,
	dstIP net.IP,
	dstPort int,
	podsByIP map[string]*v1.Pod,
	namespacesByName map[string]*v1.Namespace,
) (bool, error) {
	if len(egressRule.To) == 0 {
		return evaluatePorts(egressRule.Ports, dstPort), nil
	}

	for _, peer := range egressRule.To {
		if peer.IPBlock != nil {
			match, err := evaluateIPBlocks(peer.IPBlock, dstIP)
			if err != nil {
				return false, err
			}
			if match {
				return evaluatePorts(egressRule.Ports, dstPort), nil
			}
		}

		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			if peer.NamespaceSelector != nil {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err != nil {
					return false, fmt.Errorf("error parsing namespace selector: %w", err)
				}

				for _, ns := range namespacesByName {
					if nsSelector.Matches(labels.Set(ns.Labels)) {
						for _, pod := range podsByIP {
							if pod.Namespace == ns.Name && pod.Status.PodIP == dstIP.String() {
								if peer.PodSelector == nil {
									return evaluatePorts(egressRule.Ports, dstPort), nil
								}
								podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
								if err != nil {
									return false, fmt.Errorf("error parsing pod selector: %w", err)
								}
								if podSelector.Matches(labels.Set(pod.Labels)) {
									return evaluatePorts(egressRule.Ports, dstPort), nil
								}
							}
						}
					}
				}
			} else if peer.PodSelector != nil {
				podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
				if err != nil {
					return false, fmt.Errorf("error parsing pod selector: %w", err)
				}
				for _, pod := range podsByIP {
					if pod.Status.PodIP == dstIP.String() {
						if podSelector.Matches(labels.Set(pod.Labels)) {
							return evaluatePorts(egressRule.Ports, dstPort), nil
						}
					}
				}
			}
		}
	}
	return false, nil
}

// evaluateIngressRule checks if an ingress rule allows a connection.
func evaluateIngressRule(
	ingressRule networkingv1.NetworkPolicyIngressRule,
	srcIP net.IP,
	dstPort int,
	podsByIP map[string]*v1.Pod,
	namespacesByName map[string]*v1.Namespace,
) (bool, error) {
	if len(ingressRule.From) == 0 {
		return evaluatePorts(ingressRule.Ports, dstPort), nil
	}

	for _, peer := range ingressRule.From {
		if peer.IPBlock != nil {
			match, err := evaluateIPBlocks(peer.IPBlock, srcIP)
			if err != nil {
				return false, err
			}
			if match {
				return evaluatePorts(ingressRule.Ports, dstPort), nil
			}
		}

		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			if peer.NamespaceSelector != nil {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err != nil {
					return false, fmt.Errorf("error parsing namespace selector: %w", err)
				}

				for _, ns := range namespacesByName {
					if nsSelector.Matches(labels.Set(ns.Labels)) {
						var podSelector labels.Selector
						if peer.PodSelector != nil {
							podSelector, err = metav1.LabelSelectorAsSelector(peer.PodSelector)
							if err != nil {
								return false, fmt.Errorf("error parsing pod selector: %w", err)
							}
						}

						for _, pod := range podsByIP {
							if pod.Namespace == ns.Name && pod.Status.PodIP == srcIP.String() {
								if podSelector == nil || podSelector.Matches(labels.Set(pod.Labels)) {
									return evaluatePorts(ingressRule.Ports, dstPort), nil
								}
							}
						}
					}
				}
			} else if peer.PodSelector != nil {
				podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
				if err != nil {
					return false, fmt.Errorf("error parsing pod selector: %w", err)
				}
				for _, pod := range podsByIP {
					if pod.Status.PodIP == srcIP.String() {
						if podSelector.Matches(labels.Set(pod.Labels)) {
							return evaluatePorts(ingressRule.Ports, dstPort), nil
						}
					}
				}
			}
		}
	}
	return false, nil
}

// evaluateIPBlocks checks if an IP is within a CIDR block and not in any exceptions.
func evaluateIPBlocks(ipBlock *networkingv1.IPBlock, ip net.IP) (bool, error) {
	if ipBlock == nil {
		return true, nil
	}

	_, cidr, err := net.ParseCIDR(ipBlock.CIDR)
	if err != nil {
		return false, fmt.Errorf("error parsing CIDR '%s': %w", ipBlock.CIDR, err)
	}

	if !cidr.Contains(ip) {
		return false, nil
	}

	for _, except := range ipBlock.Except {
		_, exceptCidr, err := net.ParseCIDR(except)
		if err != nil {
			return false, fmt.Errorf("error parsing except CIDR '%s': %w", except, err)
		}
		if exceptCidr.Contains(ip) {
			return false, nil
		}
	}

	return true, nil
}

// evaluatePorts checks if a port is allowed by a list of NetworkPolicyPorts.
func evaluatePorts(networkPolicyPorts []networkingv1.NetworkPolicyPort, port int) bool {
	if len(networkPolicyPorts) == 0 {
		return true
	}

	for _, policyPort := range networkPolicyPorts {
		if policyPort.Port != nil && policyPort.Port.IntValue() == port {
			return true
		}

		if policyPort.EndPort != nil && policyPort.Port != nil {
			if int32(port) >= int32(policyPort.Port.IntValue()) && int32(port) <= *policyPort.EndPort {
				return true
			}
		}
	}
	return false
}
