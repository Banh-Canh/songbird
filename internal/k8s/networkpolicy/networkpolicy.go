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
// This function simulates the Kubernetes network policy evaluation algorithm:
// For any connection from source to destination, BOTH source egress AND destination ingress must allow the connection.
func RunNetpolCheck(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	targetIP net.IP,
	port int,
	namespace string,
	direction string,
	output string,
	showDeniedOnly bool,
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


		for _, policyType := range policyTypes {
			var directionText string
			if policyType == networkingv1.PolicyTypeEgress {
				directionText = "egress to"
			} else {
				directionText = "ingress from"
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
			var pertinentPolicies []*networkingv1.NetworkPolicy

			// Kubernetes Network Policy Rule: For a connection to be allowed,
			// BOTH source egress AND destination ingress policies must allow it
			switch policyType {
			case networkingv1.PolicyTypeEgress:
				// Get policies that could affect this specific egress connection
				pertinentPolicies = GetEffectivePoliciesForConnection(
					localPolicies,
					networkingv1.PolicyTypeEgress,
					srcPod,
					targetIP,
					port,
					podsByIP,
					namespacesByName,
				)
				// Evaluate if source pod's egress policies allow connection to target
				allowed, evalErr = EvaluatePodConnectivity(
					pertinentPolicies,
					networkingv1.PolicyTypeEgress,
					srcPod,
					targetIP,
					port,
					podsByIP,
					namespacesByName,
				)
			case networkingv1.PolicyTypeIngress:
				// Get policies that could affect this specific ingress connection
				pertinentPolicies = GetEffectivePoliciesForConnection(
					localPolicies,
					networkingv1.PolicyTypeIngress,
					srcPod,
					targetIP,
					port,
					podsByIP,
					namespacesByName,
				)
				// Evaluate if source pod can receive from target (reverse direction)
				// For ingress testing, we check if srcPod accepts connections FROM targetIP
				allowed, evalErr = EvaluatePodConnectivity(
					pertinentPolicies,
					networkingv1.PolicyTypeIngress,
					srcPod,
					targetIP,
					port,
					podsByIP,
					namespacesByName,
				)
			}

			if evalErr != nil {
				return evalErr
			}

			// Generate policy names for display - only show policies that actually applied to this evaluation
			var policyNames []string
			for _, np := range pertinentPolicies {
				policyNames = append(policyNames, fmt.Sprintf("%s/%s", np.Namespace, np.Name))
			}
			matchedPolicies := strings.Join(policyNames, ", ")
			if matchedPolicies == "" {
				matchedPolicies = "none"
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

// FilterPoliciesByType returns only the policies that apply to the specified policy type
func FilterPoliciesByType(policies []*networkingv1.NetworkPolicy, policyType networkingv1.PolicyType) []*networkingv1.NetworkPolicy {
	var filtered []*networkingv1.NetworkPolicy
	for _, policy := range policies {
		// Check if policy applies to this policy type
		if slices.Contains(policy.Spec.PolicyTypes, policyType) {
			filtered = append(filtered, policy)
		}
	}
	return filtered
}

// GetEffectivePoliciesForConnection returns only policies that are actually evaluated for a specific connection
// This provides more precise output by filtering out policies that don't participate in the decision
func GetEffectivePoliciesForConnection(
	policies []*networkingv1.NetworkPolicy,
	policyType networkingv1.PolicyType,
	targetPod *v1.Pod,
	peerIP net.IP,
	port int,
	podsByIP map[string]*v1.Pod,
	namespacesByName map[string]*v1.Namespace,
) []*networkingv1.NetworkPolicy {
	var effectivePolicies []*networkingv1.NetworkPolicy
	
	// First filter by policy type
	typedPolicies := FilterPoliciesByType(policies, policyType)
	
	// Then check which policies actually have rules that could affect this connection
	for _, policy := range typedPolicies {
		if policyType == networkingv1.PolicyTypeEgress {
			// For egress, check if any rule could allow this connection
			if len(policy.Spec.Egress) == 0 {
				// Empty egress rules means deny all - this policy affects the connection
				effectivePolicies = append(effectivePolicies, policy)
				continue
			}
			
			for _, rule := range policy.Spec.Egress {
				if couldRuleMatch(rule.To, rule.Ports, peerIP, port, podsByIP, namespacesByName, policy.Namespace) {
					effectivePolicies = append(effectivePolicies, policy)
					break // Don't need to check more rules for this policy
				}
			}
		} else if policyType == networkingv1.PolicyTypeIngress {
			// For ingress, check if any rule could allow this connection
			if len(policy.Spec.Ingress) == 0 {
				// Empty ingress rules means deny all - this policy affects the connection
				effectivePolicies = append(effectivePolicies, policy)
				continue
			}
			
			for _, rule := range policy.Spec.Ingress {
				if couldRuleMatch(rule.From, rule.Ports, peerIP, port, podsByIP, namespacesByName, policy.Namespace) {
					effectivePolicies = append(effectivePolicies, policy)
					break // Don't need to check more rules for this policy
				}
			}
		}
	}
	
	return effectivePolicies
}

// couldRuleMatch checks if a rule could potentially match the given connection
// This is a simplified check to determine if a policy is relevant to show in output
func couldRuleMatch(
	peers []networkingv1.NetworkPolicyPeer,
	ports []networkingv1.NetworkPolicyPort,
	peerIP net.IP,
	port int,
	podsByIP map[string]*v1.Pod,
	namespacesByName map[string]*v1.Namespace,
	policyNamespace string,
) bool {
	// If no peers specified, rule matches all peers
	if len(peers) == 0 {
		return true
	}
	
	// Check if any peer could match
	for _, peer := range peers {
		// Check IPBlock
		if peer.IPBlock != nil {
			_, cidr, err := net.ParseCIDR(peer.IPBlock.CIDR)
			if err == nil && cidr.Contains(peerIP) {
				// Check if IP is in exceptions
				inException := false
				for _, except := range peer.IPBlock.Except {
					_, exceptCidr, err := net.ParseCIDR(except)
					if err == nil && exceptCidr.Contains(peerIP) {
						inException = true
						break
					}
				}
				if !inException {
					return true // IP matches and not in exception
				}
			}
		}
		
		// Check pod/namespace selectors
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			_, ok := podsByIP[peerIP.String()]
			if ok {
				// Simplified check - if there's a peer pod, the rule could potentially match
				// A full evaluation would check label selectors, but for output purposes,
				// showing the policy is better than not showing it
				return true
			}
		}
	}
	
	return false
}

// EvaluateFullConnectivity performs a complete bi-directional connectivity check
// following Kubernetes network policy semantics: both source egress AND destination ingress must allow
func EvaluateFullConnectivity(
	sourcePod *v1.Pod,
	destPod *v1.Pod,
	port int,
	allNetworkPolicies []*networkingv1.NetworkPolicy,
	podsByIP map[string]*v1.Pod,
	namespacesByName map[string]*v1.Namespace,
) (bool, error) {
	// Get egress policies for source pod
	sourceEgressPolicies, err := GetLocalNetworkPoliciesForPod(sourcePod, allNetworkPolicies)
	if err != nil {
		return false, fmt.Errorf("failed to get source egress policies: %w", err)
	}

	// Get ingress policies for destination pod
	destIngressPolicies, err := GetLocalNetworkPoliciesForPod(destPod, allNetworkPolicies)
	if err != nil {
		return false, fmt.Errorf("failed to get destination ingress policies: %w", err)
	}

	// Check source egress: can source pod send to destination?
	egressAllowed, err := EvaluatePodConnectivity(
		sourceEgressPolicies,
		networkingv1.PolicyTypeEgress,
		sourcePod,
		net.ParseIP(destPod.Status.PodIP),
		port,
		podsByIP,
		namespacesByName,
	)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate source egress: %w", err)
	}

	// Check destination ingress: can destination pod receive from source?
	ingressAllowed, err := EvaluatePodConnectivity(
		destIngressPolicies,
		networkingv1.PolicyTypeIngress,
		destPod,
		net.ParseIP(sourcePod.Status.PodIP),
		port,
		podsByIP,
		namespacesByName,
	)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate destination ingress: %w", err)
	}

	// Connection is allowed only if BOTH egress and ingress allow it
	return egressAllowed && ingressAllowed, nil
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
			// Case 1: Policy peer explicitly selects a namespace (and potentially pods)
			if peer.NamespaceSelector != nil {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err == nil && nsSelector.Matches(labels.Set(namespacesByName[pod.Namespace].Labels)) {
					if peer.PodSelector != nil {
						podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
						if err == nil && podSelector.Matches(labels.Set(pod.Labels)) {
							return true
						}
					} else { // No podSelector, so it matches all pods in the namespace
						return true
					}
				}
			} else if peer.PodSelector != nil {
				// Case 2: Policy peer has a podSelector but no namespaceSelector.
				// This implicitly means pods in the same namespace as the policy.
				// We need to check if the target pod is in the same namespace as the policy.
				if np.Namespace == pod.Namespace {
					podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
					if err == nil && podSelector.Matches(labels.Set(pod.Labels)) {
						return true
					}
				}
			}
		}
	}

	// Check Egress rules for a "to" peer that matches the pod's namespace/labels.
	for _, egressRule := range np.Spec.Egress {
		for _, peer := range egressRule.To {
			// Case 1: Policy peer explicitly selects a namespace (and potentially pods)
			if peer.NamespaceSelector != nil {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err == nil && nsSelector.Matches(labels.Set(namespacesByName[pod.Namespace].Labels)) {
					if peer.PodSelector != nil {
						podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
						if err == nil && podSelector.Matches(labels.Set(pod.Labels)) {
							return true
						}
					} else { // No podSelector, so it matches all pods in the namespace
						return true
					}
				}
			} else if peer.PodSelector != nil {
				// Case 2: Policy peer has a podSelector but no namespaceSelector.
				// This implicitly means pods in the same namespace as the policy.
				// We need to check if the target pod is in the same namespace as the policy.
				if np.Namespace == pod.Namespace {
					podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
					if err == nil && podSelector.Matches(labels.Set(pod.Labels)) {
						return true
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
			// If policy has egress rules, evaluate them
			if len(netpol.Spec.Egress) > 0 {
				for _, egressRule := range netpol.Spec.Egress {
					allowed, err := evaluateEgressRule(egressRule, netpol.Namespace, peerIP, port, podsByIP, namespacesByName)
					if err != nil {
						return false, fmt.Errorf("error evaluating egress rule for policy %s: %w", netpol.Name, err)
					}
					if allowed {
						return true, nil
					}
				}
			}
			// If no egress rules or none matched, this policy denies the connection
		} else if policyType == networkingv1.PolicyTypeIngress {
			// If policy has ingress rules, evaluate them
			if len(netpol.Spec.Ingress) > 0 {
				for _, ingressRule := range netpol.Spec.Ingress {
					allowed, err := evaluateIngressRule(ingressRule, netpol.Namespace, peerIP, port, podsByIP, namespacesByName)
					if err != nil {
						return false, fmt.Errorf("error evaluating ingress rule for policy %s: %w", netpol.Name, err)
					}
					if allowed {
						return true, nil
					}
				}
			}
			// If no ingress rules or none matched, this policy denies the connection
		}
	}
	return false, nil
}

// evaluateEgressRule checks if an egress rule allows a connection.
// It now takes the policy's namespace as a new parameter.
func evaluateEgressRule(
	egressRule networkingv1.NetworkPolicyEgressRule,
	policyNamespace string,
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

		// A peer can have a PodSelector or a NamespaceSelector.
		// A NamespaceSelector without a PodSelector matches all pods in that namespace.
		// A PodSelector without a NamespaceSelector matches pods in the *policy's* namespace.
		// A combination of both matches pods with specified labels in a selected namespace.
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			peerPod, ok := podsByIP[dstIP.String()]
			if !ok {
				continue // The destination IP doesn't belong to a pod, so we can't evaluate pod/namespace selectors.
			}

			// Case 1: Explicitly selected namespace
			if peer.NamespaceSelector != nil {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err != nil {
					return false, fmt.Errorf("error parsing namespace selector: %w", err)
				}
				peerNs, ok := namespacesByName[peerPod.Namespace]
				if !ok {
					continue
				}
				if nsSelector.Matches(labels.Set(peerNs.Labels)) {
					// We've matched the namespace, now check pod labels if a podSelector exists.
					if peer.PodSelector == nil {
						return evaluatePorts(egressRule.Ports, dstPort), nil
					}
					podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
					if err != nil {
						return false, fmt.Errorf("error parsing pod selector: %w", err)
					}
					if podSelector.Matches(labels.Set(peerPod.Labels)) {
						return evaluatePorts(egressRule.Ports, dstPort), nil
					}
				}
			} else {
				// Case 2: PodSelector without a NamespaceSelector (implicit same-namespace rule)
				// Check if the destination pod is in the same namespace as the policy.
				if peerPod.Namespace == policyNamespace {
					if peer.PodSelector == nil {
						// This case should not be reached as peer.PodSelector is checked to be non-nil.
						return evaluatePorts(egressRule.Ports, dstPort), nil
					}
					podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
					if err != nil {
						return false, fmt.Errorf("error parsing pod selector: %w", err)
					}
					if podSelector.Matches(labels.Set(peerPod.Labels)) {
						return evaluatePorts(egressRule.Ports, dstPort), nil
					}
				}
			}
		}
	}
	return false, nil
}

// evaluateIngressRule checks if an ingress rule allows a connection.
// It now takes the policy's namespace as a new parameter.
func evaluateIngressRule(
	ingressRule networkingv1.NetworkPolicyIngressRule,
	policyNamespace string,
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
			peerPod, ok := podsByIP[srcIP.String()]
			if !ok {
				continue // The source IP doesn't belong to a pod, so we can't evaluate pod/namespace selectors.
			}

			// Case 1: Explicitly selected namespace
			if peer.NamespaceSelector != nil {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err != nil {
					return false, fmt.Errorf("error parsing namespace selector: %w", err)
				}
				peerNs, ok := namespacesByName[peerPod.Namespace]
				if !ok {
					continue
				}
				if nsSelector.Matches(labels.Set(peerNs.Labels)) {
					// We've matched the namespace, now check pod labels if a podSelector exists.
					if peer.PodSelector == nil {
						return evaluatePorts(ingressRule.Ports, dstPort), nil
					}
					podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
					if err != nil {
						return false, fmt.Errorf("error parsing pod selector: %w", err)
					}
					if podSelector.Matches(labels.Set(peerPod.Labels)) {
						return evaluatePorts(ingressRule.Ports, dstPort), nil
					}
				}
			} else {
				// Case 2: PodSelector without a NamespaceSelector (implicit same-namespace rule)
				// Check if the source pod is in the same namespace as the policy.
				if peerPod.Namespace == policyNamespace {
					if peer.PodSelector == nil {
						// This case should not be reached as peer.PodSelector is checked to be non-nil.
						return evaluatePorts(ingressRule.Ports, dstPort), nil
					}
					podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
					if err != nil {
						return false, fmt.Errorf("error parsing pod selector: %w", err)
					}
					if podSelector.Matches(labels.Set(peerPod.Labels)) {
						return evaluatePorts(ingressRule.Ports, dstPort), nil
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
