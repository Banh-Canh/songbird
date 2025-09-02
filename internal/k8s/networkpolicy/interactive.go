package networkpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/ktr0731/go-fuzzyfinder"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
)

// NamespaceItem represents a namespace in the interactive selector
type NamespaceItem struct {
	Name        string
	Status      string
	Description string
}

// PodItem represents a pod in the interactive selector  
type PodItem struct {
	Name        string
	Namespace   string
	IP          string
	Status      string
	Ready       string
	Description string
}

// InteractiveSelector provides fuzzy finder functionality for Kubernetes resources
type InteractiveSelector struct {
	clientset kubernetes.Interface
	ctx       context.Context
}

// NewInteractiveSelector creates a new interactive selector
func NewInteractiveSelector(clientset kubernetes.Interface, ctx context.Context) *InteractiveSelector {
	return &InteractiveSelector{
		clientset: clientset,
		ctx:       ctx,
	}
}

// SelectNamespace shows an interactive namespace selector  
func (s *InteractiveSelector) SelectNamespace() (*NamespaceItem, error) {
	return s.SelectNamespaceWithPrompt("Namespace > ")
}

// SelectNamespaceWithPrompt shows an interactive namespace selector with custom prompt
func (s *InteractiveSelector) SelectNamespaceWithPrompt(prompt string) (*NamespaceItem, error) {
	namespaces, err := s.listNamespaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	if len(namespaces) == 0 {
		return nil, fmt.Errorf("no namespaces found or insufficient permissions")
	}

	idx, err := fuzzyfinder.Find(
		namespaces,
		func(i int) string {
			return namespaces[i].Name
		},
		fuzzyfinder.WithPreviewWindow(func(i, w, h int) string {
			if i == -1 {
				return "Select a namespace"
			}
			ns := namespaces[i]
			return fmt.Sprintf(
				"Namespace: %s\nStatus: %s",
				ns.Name,
				ns.Status,
			)
		}),
		fuzzyfinder.WithPromptString(prompt),
	)
	
	if err != nil {
		return nil, err
	}

	return &namespaces[idx], nil
}

// SelectPod shows an interactive pod selector for the given namespace
func (s *InteractiveSelector) SelectPod(namespace, title string) (*PodItem, error) {
	pods, err := s.listPodsInNamespace(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to list pods in namespace %s: %w", namespace, err)
	}

	if len(pods) == 0 {
		return nil, fmt.Errorf("no pods found in namespace %s", namespace)
	}

	idx, err := fuzzyfinder.Find(
		pods,
		func(i int) string {
			return pods[i].Name
		},
		fuzzyfinder.WithPreviewWindow(func(i, w, h int) string {
			if i == -1 {
				return "Select a pod"
			}
			pod := pods[i]
			return fmt.Sprintf(
				"Pod: %s\nIP: %s\nStatus: %s\nReady: %s",
				pod.Name,
				pod.IP,
				pod.Status,
				pod.Ready,
			)
		}),
		fuzzyfinder.WithPromptString(fmt.Sprintf("%s > ", title)),
	)
	
	if err != nil {
		return nil, err
	}

	return &pods[idx], nil
}

// listNamespaces retrieves and formats namespace information
func (s *InteractiveSelector) listNamespaces() ([]NamespaceItem, error) {
	nsList, err := s.clientset.CoreV1().Namespaces().List(s.ctx, metav1.ListOptions{})
	if err != nil {
		if errors.IsForbidden(err) {
			return nil, fmt.Errorf("insufficient permissions to list namespaces. Please check your RBAC permissions")
		}
		return nil, err
	}

	var namespaces []NamespaceItem
	for _, ns := range nsList.Items {
		status := string(ns.Status.Phase)
		if status == "" {
			status = "Active"
		}

		description := ""
		if ns.Labels != nil && len(ns.Labels) > 0 {
			var importantLabels []string
			for k, v := range ns.Labels {
				// Only show common important labels
				if k == "env" || k == "environment" || k == "tier" || k == "team" {
					importantLabels = append(importantLabels, fmt.Sprintf("%s=%s", k, v))
				}
			}
			if len(importantLabels) > 0 {
				description = strings.Join(importantLabels, ", ")
			}
		}

		namespaces = append(namespaces, NamespaceItem{
			Name:        ns.Name,
			Status:      status,
			Description: description,
		})
	}

	// Sort namespaces by name for consistent ordering
	sort.Slice(namespaces, func(i, j int) bool {
		return namespaces[i].Name < namespaces[j].Name
	})

	return namespaces, nil
}

// listPodsInNamespace retrieves and formats pod information for a specific namespace
func (s *InteractiveSelector) listPodsInNamespace(namespace string) ([]PodItem, error) {
	podList, err := s.clientset.CoreV1().Pods(namespace).List(s.ctx, metav1.ListOptions{})
	if err != nil {
		if errors.IsForbidden(err) {
			return nil, fmt.Errorf("insufficient permissions to list pods in namespace %s. Please check your RBAC permissions", namespace)
		}
		return nil, err
	}

	var pods []PodItem
	for _, pod := range podList.Items {
		// Skip pods that don't have an IP yet
		if pod.Status.PodIP == "" {
			continue
		}

		status := string(pod.Status.Phase)
		ready := s.getPodReadiness(&pod)
		
		description := ""
		if pod.Labels != nil && len(pod.Labels) > 0 {
			var importantLabels []string
			for k, v := range pod.Labels {
				// Only show common important labels
				if k == "app" || k == "version" || k == "env" || k == "tier" {
					importantLabels = append(importantLabels, fmt.Sprintf("%s=%s", k, v))
				}
			}
			if len(importantLabels) > 0 {
				description = strings.Join(importantLabels, ", ")
			}
		}

		pods = append(pods, PodItem{
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			IP:          pod.Status.PodIP,
			Status:      status,
			Ready:       ready,
			Description: description,
		})
	}

	// Sort pods by name for consistent ordering
	sort.Slice(pods, func(i, j int) bool {
		return pods[i].Name < pods[j].Name
	})

	return pods, nil
}


// getPodReadiness calculates pod readiness status
func (s *InteractiveSelector) getPodReadiness(pod *v1.Pod) string {
	if pod.Status.Phase != v1.PodRunning {
		return "N/A"
	}

	ready := 0
	total := 0
	for _, condition := range pod.Status.Conditions {
		if condition.Type == v1.PodReady {
			if condition.Status == v1.ConditionTrue {
				ready = 1
			}
			total = 1
			break
		}
	}

	// If no ready condition found, check container readiness
	if total == 0 {
		for _, containerStatus := range pod.Status.ContainerStatuses {
			total++
			if containerStatus.Ready {
				ready++
			}
		}
	}

	return fmt.Sprintf("%d/%d", ready, total)
}

// CheckPermissions verifies if the user has the necessary permissions
func (s *InteractiveSelector) CheckPermissions() error {
	// Try to list namespaces to check basic permissions
	_, err := s.clientset.CoreV1().Namespaces().List(s.ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		if errors.IsForbidden(err) {
			return fmt.Errorf("insufficient permissions: %w\n\nYou need at least the following permissions:\n- namespaces: list, get\n- pods: list, get\n- networkpolicies: list, get", err)
		}
		return fmt.Errorf("failed to check permissions: %w", err)
	}
	return nil
}

// InteractiveNetworkPolicyCheck performs the complete interactive flow for network policy checking
func (s *InteractiveSelector) InteractiveNetworkPolicyCheck(port int, direction string, output string, deniedOnly bool) error {
	// Step 1: Check permissions first
	if err := s.CheckPermissions(); err != nil {
		return err
	}

	// Step 2: Select source namespace
	sourceNamespace, err := s.SelectNamespaceWithPrompt("Source namespace > ")
	if err != nil {
		return fmt.Errorf("failed to select source namespace: %w", err)
	}

	// Step 3: Select source pod
	sourcePod, err := s.SelectPod(sourceNamespace.Name, "source pod")
	if err != nil {
		return fmt.Errorf("failed to select source pod: %w", err)
	}

	// Step 4: Select destination namespace only
	destNamespace, err := s.SelectNamespaceWithPrompt("Destination namespace > ")
	if err != nil {
		return fmt.Errorf("failed to select destination namespace: %w", err)
	}


	// Step 6: Use RunPodToNamespaceCheck for consistent output with pod-to-address
	if clientset, ok := s.clientset.(*kubernetes.Clientset); ok {
		return s.RunPodToNamespaceCheck(clientset, sourcePod, destNamespace.Name, port, direction, output, deniedOnly)
	}
	return fmt.Errorf("clientset type assertion failed - cannot run network policy check")
}

// RunPodToNamespaceCheck evaluates connectivity from a specific source pod to all pods in a destination namespace
// This provides output consistent with the standard RunNetpolCheck function
func (s *InteractiveSelector) RunPodToNamespaceCheck(
	clientset *kubernetes.Clientset,
	sourcePod *PodItem,
	destNamespace string,
	port int,
	direction string,
	output string,
	showDeniedOnly bool,
) error {
	// Pre-fetch all necessary resources
	allPods, err := clientset.CoreV1().Pods("").List(s.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list all pods: %w", err)
	}
	allNamespaces, err := clientset.CoreV1().Namespaces().List(s.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list all namespaces: %w", err)
	}
	npl, err := clientset.NetworkingV1().NetworkPolicies("").List(s.ctx, metav1.ListOptions{})
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

	// Get source pod object
	srcPodObj := podsByIP[sourcePod.IP]
	if srcPodObj == nil {
		return fmt.Errorf("source pod not found in cluster: %s", sourcePod.IP)
	}

	// Get destination namespace pods
	var destPods []v1.Pod
	for _, pod := range allPods.Items {
		if pod.Namespace == destNamespace && pod.Status.PodIP != "" {
			destPods = append(destPods, pod)
		}
	}

	if len(destPods) == 0 {
		return nil
	}

	// Get all relevant policies for both egress and ingress (since we're doing bidirectional check)
	var relevantPolicies []*networkingv1.NetworkPolicy
	switch direction {
	case "egress":
		relevantPolicies = FilterPoliciesByType(nps, networkingv1.PolicyTypeEgress)
	case "ingress":
		relevantPolicies = FilterPoliciesByType(nps, networkingv1.PolicyTypeIngress)
	case "all":
		egressPolicies := FilterPoliciesByType(nps, networkingv1.PolicyTypeEgress)
		ingressPolicies := FilterPoliciesByType(nps, networkingv1.PolicyTypeIngress)
		relevantPolicies = append(egressPolicies, ingressPolicies...)
	default:
		return fmt.Errorf("invalid direction: %s", direction)
	}
	
	var results []CheckResult
	allowedCount := 0
	deniedCount := 0

	// Check connectivity to each destination pod
	for _, destPod := range destPods {
		destIP := net.ParseIP(destPod.Status.PodIP)
		srcIP := net.ParseIP(srcPodObj.Status.PodIP)

		if direction == "all" {
			// For "all", create separate entries for both egress and ingress evaluation
			directions := []struct {
				policyType    networkingv1.PolicyType
				directionText string
			}{
				{networkingv1.PolicyTypeEgress, "egress to"},
				{networkingv1.PolicyTypeIngress, "ingress from"},
			}

			for _, dir := range directions {
				var allowed bool
				var evalErr error
				var effectivePolicies []*networkingv1.NetworkPolicy

				if dir.policyType == networkingv1.PolicyTypeEgress {
					// Evaluate egress from source to destination
					egressPolicies := FilterPoliciesByType(relevantPolicies, networkingv1.PolicyTypeEgress)
					allowed, evalErr = EvaluatePodConnectivity(egressPolicies, networkingv1.PolicyTypeEgress, srcPodObj, destIP, port, podsByIP, namespacesByName)
					effectivePolicies = GetEffectivePoliciesForConnection(egressPolicies, networkingv1.PolicyTypeEgress, srcPodObj, destIP, port, podsByIP, namespacesByName)
				} else {
					// Evaluate ingress to destination from source
					ingressPolicies := FilterPoliciesByType(relevantPolicies, networkingv1.PolicyTypeIngress)
					allowed, evalErr = EvaluatePodConnectivity(ingressPolicies, networkingv1.PolicyTypeIngress, &destPod, srcIP, port, podsByIP, namespacesByName)
					effectivePolicies = GetEffectivePoliciesForConnection(ingressPolicies, networkingv1.PolicyTypeIngress, &destPod, srcIP, port, podsByIP, namespacesByName)
				}

				if evalErr != nil {
					return fmt.Errorf("failed to evaluate %s connectivity to pod %s: %w", dir.directionText, destPod.Name, evalErr)
				}

				status := "DENIED ❌"
				if allowed {
					status = "ALLOWED ✅"
					allowedCount++
				} else {
					deniedCount++
				}

				if !showDeniedOnly || !allowed {
					policyNames := make([]string, len(effectivePolicies))
					for i, policy := range effectivePolicies {
						policyNames[i] = fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
					}

					results = append(results, CheckResult{
						Namespace:       sourcePod.Namespace, // SOURCE pod namespace
						Pod:             sourcePod.Name,      // SOURCE pod name
						Direction:       dir.directionText,
						Target:          fmt.Sprintf("%s/%s", destPod.Namespace, destPod.Name),
						Port:            port,
						NetworkPolicies: policyNames,
						Status:          status,
					})
				}
			}
		} else {
			// Single direction evaluation
			allowed, err := EvaluateFullConnectivity(srcPodObj, &destPod, port, relevantPolicies, podsByIP, namespacesByName)
			if err != nil {
				return fmt.Errorf("failed to evaluate connectivity to pod %s: %w", destPod.Name, err)
			}

			status := "DENIED ❌"
			if allowed {
				status = "ALLOWED ✅"
				allowedCount++
			} else {
				deniedCount++
			}

			if !showDeniedOnly || !allowed {
				// Get effective policies for this specific connection
				var effectivePolicies []*networkingv1.NetworkPolicy
				if direction == "egress" {
					effectivePolicies = GetEffectivePoliciesForConnection(relevantPolicies, networkingv1.PolicyTypeEgress, srcPodObj, destIP, port, podsByIP, namespacesByName)
				} else {
					effectivePolicies = GetEffectivePoliciesForConnection(relevantPolicies, networkingv1.PolicyTypeIngress, &destPod, srcIP, port, podsByIP, namespacesByName)
				}

				policyNames := make([]string, len(effectivePolicies))
				for i, policy := range effectivePolicies {
					policyNames[i] = fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
				}

				// Set direction text
				var directionText string
				if direction == "egress" {
					directionText = "egress to"
				} else {
					directionText = "ingress from"
				}

				results = append(results, CheckResult{
					Namespace:       sourcePod.Namespace, // SOURCE pod namespace
					Pod:             sourcePod.Name,      // SOURCE pod name
					Direction:       directionText,
					Target:          fmt.Sprintf("%s/%s", destPod.Namespace, destPod.Name),
					Port:            port,
					NetworkPolicies: policyNames,
					Status:          status,
				})
			}
		}
	}

	// Display results using the same format as RunNetpolCheck
	if output == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	}

	// Text output - match exact format from main networkpolicy.go
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if output == "wide" {
		fmt.Fprintln(w, "NAMESPACE\tPOD\tDIRECTION\tTARGET\tPORT\tNETWORK_POLICIES\tSTATUS")
		for _, result := range results {
			policies := strings.Join(result.NetworkPolicies, ", ")
			if policies == "" {
				policies = "none"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
				result.Namespace, result.Pod, result.Direction, result.Target, result.Port, policies, result.Status)
		}
	} else {
		fmt.Fprintln(w, "NAMESPACE\tPOD\tDIRECTION\tTARGET\tPORT\tSTATUS")
		for _, result := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
				result.Namespace, result.Pod, result.Direction, result.Target, result.Port, result.Status)
		}
	}
	w.Flush()
	return nil
}

