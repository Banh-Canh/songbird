package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"slices"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// GetLocalNetworkPoliciesForPod returns a slice of NetworkPolicies that directly apply to the given pod.
// A policy directly applies if it is in the same namespace and its podSelector matches the pod.
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
	clientset *kubernetes.Clientset,
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
	for _, np := range allNetworkPolicies {
		// Skip policies in the same namespace, as they were handled by GetLocalNetworkPoliciesForPod.
		if np.Namespace == pod.Namespace {
			continue
		}

		// Check if the policy's ingress or egress rules explicitly target the pod.
		if doesPolicyTargetPod(clientset, np, pod) {
			policiesForPod = append(policiesForPod, np)
		}
	}

	return policiesForPod, nil
}

// doesPolicyTargetPod checks if a network policy's ingress or egress rules
func doesPolicyTargetPod(clientset *kubernetes.Clientset, np *networkingv1.NetworkPolicy, pod *v1.Pod) bool {
	// Check Ingress rules for a "from" peer that matches the pod's namespace/labels.
	for _, ingressRule := range np.Spec.Ingress {
		for _, peer := range ingressRule.From {
			if peer.NamespaceSelector != nil {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err == nil {
					// Match the namespace of the target pod
					if nsSelector.Matches(labels.Set(map[string]string{"kubernetes.io/metadata.name": pod.Namespace})) {
						// Namespace matches. Now check the pod selector if it exists.
						if peer.PodSelector != nil {
							podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
							if err == nil && podSelector.Matches(labels.Set(pod.Labels)) {
								return true // Found a match!
							}
						} else {
							return true // Namespace matches and no pod selector specified, so it matches all pods in that namespace.
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
					if nsSelector.Matches(labels.Set(map[string]string{"kubernetes.io/metadata.name": pod.Namespace})) {
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
	clientset *kubernetes.Clientset,
	networkPolicies []*networkingv1.NetworkPolicy, policyType networkingv1.PolicyType,
	targetPod *v1.Pod, peerIP net.IP, port int,
) (bool, error) {
	var appliesToPolicyType bool
	// Check if any of the network policies apply to the specified policyType (Ingress or Egress).
	for _, netpol := range networkPolicies {
		if slices.Contains(netpol.Spec.PolicyTypes, policyType) {
			appliesToPolicyType = true
			break
		}
	}
	// If no policies apply to this traffic type, the connection is allowed !
	if !appliesToPolicyType {
		return true, nil
	}
	// try iterate through the network policies again to evaluate the specific rules :)
	for _, netpol := range networkPolicies {
		// Skip policies that do not apply to the current policyType.
		if !slices.Contains(netpol.Spec.PolicyTypes, policyType) {
			continue
		}
		// Handle Egress policies.
		if policyType == networkingv1.PolicyTypeEgress {
			// If an egress policy has no rules, it doesn't restrict traffic, so continue
			if len(netpol.Spec.Egress) == 0 {
				continue
			}
			// Evaluate each egress rule for a match.
			for _, egressRule := range netpol.Spec.Egress {
				allowed, err := evaluateEgressRule(clientset, egressRule, targetPod, peerIP, port)
				if err != nil {
					return false, fmt.Errorf("error evaluating egress rule for policy %s: %w", netpol.Name, err)
				}
				// If a single egress rule allows the connection, the connection is permitted.
				if allowed {
					return true, nil
				}
			}
		} else if policyType == networkingv1.PolicyTypeIngress { // Handle Ingress policies.
			// If an ingress policy has no rules, it doesn't restrict traffic, so continue to the next policy.
			if len(netpol.Spec.Ingress) == 0 {
				continue
			}

			// Evaluate each ingress rule for a match.
			for _, ingressRule := range netpol.Spec.Ingress {
				allowed, err := evaluateIngressRule(clientset, ingressRule, targetPod, peerIP, port)
				if err != nil {
					return false, fmt.Errorf("error evaluating ingress rule for policy %s: %w", netpol.Name, err)
				}
				// If a single ingress rule allows the connection, the connection is permitted.
				if allowed {
					return true, nil
				}
			}
		}
	}

	// If no rules in any applicable policy allowed the connection, it is denied.
	return false, nil
}

// evaluateEgressRule checks if an egress rule allows a connection.
func evaluateEgressRule(
	clientset *kubernetes.Clientset,
	egressRule networkingv1.NetworkPolicyEgressRule,
	srcPod *v1.Pod,
	dstIP net.IP,
	dstPort int,
) (bool, error) {
	// If the "to" field is empty, this egress rule applies to all destinations.
	// The connection is allowed if the port matches.
	if len(egressRule.To) == 0 {
		return evaluatePorts(egressRule.Ports, dstPort), nil
	}

	// The connection is allowed if it matches any of the peers (source or destination ip, in the network vocab).
	for _, peer := range egressRule.To {
		// Check for an IPBlock match.
		if peer.IPBlock != nil {
			match, err := evaluateIPBlocks(peer.IPBlock, dstIP)
			if err != nil {
				return false, err
			}
			// If the destination IP is within the IPBlock, check if the port is allowed.
			if match {
				return evaluatePorts(egressRule.Ports, dstPort), nil
			}
		}

		// Check for PodSelector and NamespaceSelector matches.
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			// Handle cases with a NamespaceSelector.
			if peer.NamespaceSelector != nil {
				// Convert the label selector from the policy to a selector object.
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err != nil {
					return false, fmt.Errorf("error parsing namespace selector: %w", err)
				}

				// List all namespaces that match the selector.
				namespaces, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{
					LabelSelector: nsSelector.String(),
				})
				if err != nil {
					return false, fmt.Errorf("error listing namespaces: %w", err)
				}

				// Iterate through the matching namespaces.
				for _, ns := range namespaces.Items {
					podsInNs, err := clientset.CoreV1().Pods(ns.Name).List(context.Background(), metav1.ListOptions{})
					if err != nil {
						return false, fmt.Errorf("error listing pods in namespace %s: %w", ns.Name, err)
					}
					// Iterate through the pods to find a match for the destination IP.
					for _, pod := range podsInNs.Items {
						if pod.Status.PodIP == dstIP.String() {
							// If a PodSelector is not specified, a match is found. Check the port.
							if peer.PodSelector == nil {
								return evaluatePorts(egressRule.Ports, dstPort), nil
							}
							// If a PodSelector is specified, convert it and check for a label match.
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
				continue
			}

			// Handle cases with only a PodSelector (same namespace).
			if peer.PodSelector != nil && peer.NamespaceSelector == nil {
				// Convert the PodSelector to a selector object.
				podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
				if err != nil {
					return false, fmt.Errorf("error parsing pod selector: %w", err)
				}
				pods, err := clientset.CoreV1().Pods(srcPod.Namespace).List(context.Background(), metav1.ListOptions{
					LabelSelector: podSelector.String(),
				})
				if err != nil {
					return false, fmt.Errorf("error listing pods in namespace %s: %w", srcPod.Namespace, err)
				}
				for _, pod := range pods.Items {
					if pod.Status.PodIP == dstIP.String() {
						return evaluatePorts(egressRule.Ports, dstPort), nil
					}
				}
			}
		}
	}
	return false, nil
}

// evaluateIngressRule checks if an ingress rule allows a connection.
func evaluateIngressRule(
	clientset *kubernetes.Clientset,
	ingressRule networkingv1.NetworkPolicyIngressRule,
	targetPod *v1.Pod,
	srcIP net.IP,
	dstPort int,
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

				namespaces, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{
					LabelSelector: nsSelector.String(),
				})
				if err != nil {
					return false, fmt.Errorf("error listing namespaces: %w", err)
				}
				for _, ns := range namespaces.Items {
					var podSelector labels.Selector
					if peer.PodSelector != nil {
						podSelector, err = metav1.LabelSelectorAsSelector(peer.PodSelector)
						if err != nil {
							return false, fmt.Errorf("error parsing pod selector: %w", err)
						}
					}

					listOptions := metav1.ListOptions{}
					if podSelector != nil {
						listOptions.LabelSelector = podSelector.String()
					}

					podsInNs, err := clientset.CoreV1().Pods(ns.Name).List(context.Background(), listOptions)
					if err != nil {
						return false, fmt.Errorf("error listing pods in namespace %s: %w", ns.Name, err)
					}
					for _, pod := range podsInNs.Items {
						if pod.Status.PodIP == srcIP.String() {
							return evaluatePorts(ingressRule.Ports, dstPort), nil
						}
					}
				}
				continue
			}
			if peer.PodSelector != nil && peer.NamespaceSelector == nil {
				podSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
				if err != nil {
					return false, fmt.Errorf("error parsing pod selector: %w", err)
				}
				pods, err := clientset.CoreV1().Pods(targetPod.Namespace).List(context.Background(), metav1.ListOptions{
					LabelSelector: podSelector.String(),
				})
				if err != nil {
					return false, fmt.Errorf("error listing pods in namespace %s: %w", targetPod.Namespace, err)
				}
				for _, pod := range pods.Items {
					if pod.Status.PodIP == srcIP.String() {
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
