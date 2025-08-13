package networkpolicy

import (
	"fmt"
	"net"
	"slices"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

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
				allowed, err := evaluateEgressRule(egressRule, targetPod, peerIP, port, podsByIP, namespacesByName)
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
				allowed, err := evaluateIngressRule(ingressRule, targetPod, peerIP, port, podsByIP, namespacesByName)
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
	srcPod *v1.Pod,
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
					if pod.Namespace == srcPod.Namespace && pod.Status.PodIP == dstIP.String() {
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
	targetPod *v1.Pod,
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
					if pod.Namespace == targetPod.Namespace && pod.Status.PodIP == srcIP.String() {
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
