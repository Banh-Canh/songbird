package networkpolicy_test

import (
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Banh-Canh/songbird/internal/k8s/networkpolicy"
)

// Helper functions for test setup
func newPod(name, namespace, ip string, podLabels map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    podLabels,
		},
		Status: v1.PodStatus{
			PodIP: ip,
		},
	}
}

func newNamespace(name string, nsLabels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: nsLabels,
		},
	}
}

func newNetworkPolicy(name, namespace string, podSelector labels.Set, policyTypes ...networkingv1.PolicyType) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podSelector},
			PolicyTypes: policyTypes,
		},
	}
}

// Test for GetLocalNetworkPoliciesForPod
func TestGetLocalNetworkPoliciesForPod(t *testing.T) {
	pod := newPod("test-pod", "default", "10.0.0.1", map[string]string{"app": "web", "tier": "frontend"})

	policies := []*networkingv1.NetworkPolicy{
		newNetworkPolicy("policy-a", "default", labels.Set{"app": "web"}, networkingv1.PolicyTypeIngress),
		newNetworkPolicy("policy-b", "default", labels.Set{"tier": "frontend"}, networkingv1.PolicyTypeEgress),
		newNetworkPolicy("policy-c", "other-namespace", labels.Set{"app": "web"}, networkingv1.PolicyTypeIngress),
		newNetworkPolicy("policy-d", "default", labels.Set{"app": "db"}, networkingv1.PolicyTypeIngress),
	}

	t.Run("should find policies in the same namespace with matching labels", func(t *testing.T) {
		matchingPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(pod, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(matchingPolicies) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(matchingPolicies))
		}

		foundA, foundB := false, false
		for _, p := range matchingPolicies {
			if p.Name == "policy-a" {
				foundA = true
			}
			if p.Name == "policy-b" {
				foundB = true
			}
		}
		if !foundA || !foundB {
			t.Fatalf("expected to find policies 'policy-a' and 'policy-b', but didn't")
		}
	})

	t.Run("should return no policies if no labels match", func(t *testing.T) {
		podNoLabels := newPod("pod-no-labels", "default", "10.0.0.2", map[string]string{"env": "test"})
		matchingPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(podNoLabels, policies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(matchingPolicies) != 0 {
			t.Fatalf("expected 0 policies, got %d", len(matchingPolicies))
		}
	})
}

// Test for GetAllAffectingNetworkPolicies
func TestGetAllAffectingNetworkPolicies(t *testing.T) {
	targetPod := newPod("api-pod", "app-namespace", "10.0.0.10", map[string]string{"app": "api"})

	allPods := &v1.PodList{
		Items: []v1.Pod{
			*targetPod,
			*newPod("client-pod", "default", "10.0.0.5", map[string]string{"app": "client"}),
		},
	}
	allNamespaces := &v1.NamespaceList{
		Items: []v1.Namespace{
			*newNamespace("app-namespace", map[string]string{"environment": "production"}),
			*newNamespace("default", map[string]string{"environment": "production"}),
		},
	}

	localPolicy := newNetworkPolicy("local-api-policy", "app-namespace", labels.Set{"app": "api"}, networkingv1.PolicyTypeIngress)
	remotePolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "remote-client-policy",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: labels.Set{"app": "client"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: labels.Set{"environment": "production"}},
							PodSelector:       &metav1.LabelSelector{MatchLabels: labels.Set{"app": "api"}},
						},
					},
				},
			},
		},
	}

	allNetworkPolicies := []*networkingv1.NetworkPolicy{localPolicy, remotePolicy}

	t.Run("should find both local and remote policies that affect the pod", func(t *testing.T) {
		affectingPolicies, err := networkpolicy.GetAllAffectingNetworkPolicies(allPods, allNamespaces, targetPod, allNetworkPolicies)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(affectingPolicies) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(affectingPolicies))
		}

		foundLocal, foundRemote := false, false
		for _, p := range affectingPolicies {
			if p.Name == "local-api-policy" {
				foundLocal = true
			}
			if p.Name == "remote-client-policy" {
				foundRemote = true
			}
		}
		if !foundLocal || !foundRemote {
			t.Fatalf("expected to find local and remote policies, but didn't")
		}
	})

	t.Run("should only find local policies if no remote policies match", func(t *testing.T) {
		nonMatchingRemotePolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "non-matching", Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: labels.Set{"app": "other"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{PodSelector: &metav1.LabelSelector{MatchLabels: labels.Set{"app": "other"}}},
						},
					},
				},
			},
		}

		policiesWithNonMatch := []*networkingv1.NetworkPolicy{localPolicy, nonMatchingRemotePolicy}
		affectingPolicies, err := networkpolicy.GetAllAffectingNetworkPolicies(allPods, allNamespaces, targetPod, policiesWithNonMatch)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(affectingPolicies) != 1 {
			t.Fatalf("expected 1 policy, got %d", len(affectingPolicies))
		}
		if affectingPolicies[0].Name != "local-api-policy" {
			t.Fatalf("expected to find only the local policy, but found %s", affectingPolicies[0].Name)
		}
	})
}

// Test for EvaluatePodConnectivity - Comprehensive network policy test scenarios
func TestEvaluatePodConnectivity(t *testing.T) {
	// Common setup for all test scenarios
	setupPods := func() (map[string]*v1.Pod, map[string]*v1.Namespace) {
		targetPod := newPod("target-pod", "target-namespace", "10.0.0.10", map[string]string{"app": "api", "tier": "backend"})
		peerPod := newPod("peer-pod", "peer-namespace", "10.0.0.5", map[string]string{"app": "client", "tier": "frontend"})
		samePod := newPod("same-pod", "target-namespace", "10.0.0.11", map[string]string{"app": "worker"})
		
		podsByIP := map[string]*v1.Pod{
			targetPod.Status.PodIP: targetPod,
			peerPod.Status.PodIP:   peerPod,
			samePod.Status.PodIP:   samePod,
		}
		namespacesByName := map[string]*v1.Namespace{
			"peer-namespace":   newNamespace("peer-namespace", map[string]string{"env": "prod", "zone": "us-east"}),
			"target-namespace": newNamespace("target-namespace", map[string]string{"kubernetes.io/metadata.name": "target-namespace", "env": "prod"}),
		}
		return podsByIP, namespacesByName
	}
	
	podsByIP, namespacesByName := setupPods()
	targetPod := podsByIP["10.0.0.10"]
	peerPod := podsByIP["10.0.0.5"]

	// Test 1: Basic Ingress - Allow specific pod from specific namespace
	t.Run("Ingress: should allow connection when policy explicitly allows specific pod from specific namespace", func(t *testing.T) {
		ingressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-specific-pod",
				Namespace: targetPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
								NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8080}},
						},
					},
				},
			},
		}
		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{ingressPolicy},
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP(peerPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection to be allowed, but it was denied")
		}
	})

	// Test 2: Ingress Deny - Wrong pod labels
	t.Run("Ingress: should deny connection when pod labels don't match policy", func(t *testing.T) {
		ingressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deny-wrong-labels",
				Namespace: targetPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "non-existent"}}},
						},
					},
				},
			},
		}
		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{ingressPolicy},
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP(peerPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected connection to be denied, but it was allowed")
		}
	})

	// Test 3: Basic Egress - Allow specific destination
	t.Run("Egress: should allow connection when policy explicitly allows specific destination", func(t *testing.T) {
		egressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-specific-destination",
				Namespace: peerPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
								NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8080}},
						},
					},
				},
			},
		}
		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{egressPolicy},
			networkingv1.PolicyTypeEgress,
			peerPod,
			net.ParseIP(targetPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection to be allowed, but it was denied")
		}
	})

	t.Run("Egress: should handle CIDR blocks correctly", func(t *testing.T) {
		egressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: peerPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								IPBlock: &networkingv1.IPBlock{
									CIDR:   "10.0.0.0/24",
									Except: []string{"10.0.0.5/32"},
								},
							},
						},
					},
				},
			},
		}
		// Test allowed IP
		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{egressPolicy},
			networkingv1.PolicyTypeEgress,
			peerPod,
			net.ParseIP("10.0.0.6"),
			80,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection to be allowed, but it was denied")
		}

		// Test excepted IP
		allowed, err = networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{egressPolicy},
			networkingv1.PolicyTypeEgress,
			peerPod,
			net.ParseIP("10.0.0.5"),
			80,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected connection to be denied by 'except' rule, but it was allowed")
		}
	})

	t.Run("Ingress: should allow connection if peer matches namespaceSelector and podSelector", func(t *testing.T) {
		targetPod := newPod("target-pod-2", "prod", "10.0.1.10", map[string]string{"app": "db"})
		peerPod := newPod("peer-pod-2", "dev", "10.0.1.5", map[string]string{"app": "web"})
		podsByIP := map[string]*v1.Pod{
			targetPod.Status.PodIP: targetPod,
			peerPod.Status.PodIP:   peerPod,
		}
		namespacesByName := map[string]*v1.Namespace{
			"dev":  newNamespace("dev", map[string]string{"env": "dev"}),
			"prod": newNamespace("prod", map[string]string{"env": "prod"}),
		}

		ingressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: targetPod.Namespace},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: targetPod.Labels},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: labels.Set{"env": "prod"}},
						PodSelector:       &metav1.LabelSelector{MatchLabels: targetPod.Labels},
					}},
				}},
			},
		}

		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{ingressPolicy},
			networkingv1.PolicyTypeIngress,
			peerPod,
			net.ParseIP(targetPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection to be allowed via namespace and pod selectors, but it was denied")
		}
	})

	t.Run("Egress: should handle CIDR with 'except' for a single IP", func(t *testing.T) {
		egressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				PodSelector: metav1.LabelSelector{}, // Applies to all pods in the namespace
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To: []networkingv1.NetworkPolicyPeer{{
						IPBlock: &networkingv1.IPBlock{
							CIDR:   "10.0.0.0/8",
							Except: []string{"10.0.1.0/24"},
						},
					}},
				}},
			},
		}

		sourcePod := newPod("source-pod", "default", "10.0.2.1", nil)
		podsByIP := map[string]*v1.Pod{sourcePod.Status.PodIP: sourcePod}

		// Test an IP inside the CIDR but outside the 'except' range
		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{egressPolicy},
			networkingv1.PolicyTypeEgress,
			sourcePod,
			net.ParseIP("10.0.2.2"),
			80,
			podsByIP,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection to be allowed by CIDR rule")
		}

		// Test an IP inside the 'except' range
		denied, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{egressPolicy},
			networkingv1.PolicyTypeEgress,
			sourcePod,
			net.ParseIP("10.0.1.100"),
			80,
			podsByIP,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if denied {
			t.Fatal("expected connection to be denied by 'except' rule")
		}
	})

	t.Run("Egress: should deny connection if no egress rule exists", func(t *testing.T) {
		// A Network Policy with a PolicyType of Egress but no Egress rules
		// means all egress traffic is denied.
		egressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: labels.Set{"app": "client"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress:      []networkingv1.NetworkPolicyEgressRule{}, // Empty egress rule list
			},
		}
		targetPod := newPod("peer-pod-no-egress", "default", "10.0.0.20", map[string]string{"app": "client"})
		podsByIP := map[string]*v1.Pod{targetPod.Status.PodIP: targetPod}

		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{egressPolicy},
			networkingv1.PolicyTypeEgress,
			peerPod,
			net.ParseIP(targetPod.Status.PodIP),
			80,
			podsByIP,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected connection to be denied because of an empty egress list, but it was allowed")
		}
	})

	t.Run("Ingress: should deny connection if no ingress rule exists", func(t *testing.T) {
		// A Network Policy with a PolicyType of Ingress but no Ingress rules
		// means all ingress traffic is denied.
		ingressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: labels.Set{"app": "server"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{}, // Empty ingress rule list
			},
		}
		targetPod := newPod("target-pod-no-ingress", "default", "10.0.0.30", map[string]string{"app": "server"})
		podsByIP := map[string]*v1.Pod{targetPod.Status.PodIP: targetPod}

		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{ingressPolicy},
			networkingv1.PolicyTypeIngress,
			peerPod,
			net.ParseIP(targetPod.Status.PodIP),
			80,
			podsByIP,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected connection to be denied because of an empty ingress list, but it was allowed")
		}
	})

	t.Run("Ingress: should deny if the pod is not in the same namespace. It doesn't match the in namespace rule.", func(t *testing.T) {
		// A Network Policy with a PolicyType of Ingress but no Ingress rules
		// means all ingress traffic is denied.
		ingressPolicy := &networkingv1.NetworkPolicy{
			Spec: networkingv1.NetworkPolicySpec{
				// The podSelector is empty, meaning it selects all pods in the namespace.
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				// The Ingress rule list. An empty podSelector means it allows traffic from all pods
				// within the same namespace.
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{},
							},
						},
					},
				},
				// The Egress rule list. An empty podSelector means it allows traffic to all pods
				// within the same namespace.
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{},
							},
						},
					},
				},
			},
		}
		targetPod := newPod("target-pod", "default", "10.0.0.30", map[string]string{"dummy": "dummy"})
		peerPod := newPod("peer-pod", "monitoring", "10.0.1.5", map[string]string{"app": "web"})
		namespacesByName := map[string]*v1.Namespace{
			"default":    newNamespace("default", map[string]string{"env": "dev"}),
			"monitoring": newNamespace("monitoring", map[string]string{"env": "prod"}),
		}

		podsByIP := map[string]*v1.Pod{targetPod.Status.PodIP: targetPod}

		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{ingressPolicy},
			networkingv1.PolicyTypeIngress,
			peerPod,
			net.ParseIP(targetPod.Status.PodIP),
			80,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected connection to be denied because of an empty ingress list, but it was allowed")
		}
	})
	t.Run("Ingress: should allow traffic when one policy allows and another denies", func(t *testing.T) {
		// --- Setup ---
		// A target pod selected by both policies
		targetPod := newPod("api-server", "default", "10.1.1.1", map[string]string{"app": "api"})
		// The source pod that should be allowed by the first policy
		allowedSourcePod := newPod("client-app", "default", "10.1.1.2", map[string]string{"role": "client"})
		// A different source pod that is NOT allowed by the first policy, but is by the second
		otherAllowedSourcePod := newPod("metrics-scraper", "default", "10.1.1.3", map[string]string{"role": "monitoring"})

		podsByIP := map[string]*v1.Pod{
			targetPod.Status.PodIP:             targetPod,
			allowedSourcePod.Status.PodIP:      allowedSourcePod,
			otherAllowedSourcePod.Status.PodIP: otherAllowedSourcePod,
		}
		namespacesByName := map[string]*v1.Namespace{
			"default": newNamespace("default", map[string]string{"kubernetes.io/metadata.name": "default"}),
		}

		// Policy A: Applies to 'app: api' and allows ingress from pods with 'role: client'
		policyA := newNetworkPolicy("allow-clients", "default", labels.Set{"app": "api"}, networkingv1.PolicyTypeIngress)
		policyA.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{PodSelector: &metav1.LabelSelector{MatchLabels: labels.Set{"role": "client"}}},
				},
			},
		}

		policyB := newNetworkPolicy("allow-monitoring", "default", labels.Set{"app": "api"}, networkingv1.PolicyTypeIngress)
		policyB.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{PodSelector: &metav1.LabelSelector{MatchLabels: labels.Set{"role": "monitoring"}}},
				},
			},
		}

		allApplicablePolicies := []*networkingv1.NetworkPolicy{policyA, policyB}

		allowed, err := networkpolicy.EvaluatePodConnectivity(
			allApplicablePolicies,
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP(allowedSourcePod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection to be allowed by the union of policies, but it was denied")
		}

		denied, err := networkpolicy.EvaluatePodConnectivity(
			allApplicablePolicies,
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP("192.168.10.5"), // A random, un-allowed IP
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error during deny check: %v", err)
		}
		if denied {
			t.Fatal("expected connection from an unknown source to be denied, but it was allowed")
		}
	})

	// Test 11: Port-specific rules
	t.Run("Should respect port restrictions in network policies", func(t *testing.T) {
		portPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "port-specific",
				Namespace: targetPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
					}},
					Ports: []networkingv1.NetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8080}}, // Only allow port 8080
					},
				}},
			},
		}

		// Test allowed port 8080
		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{portPolicy},
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP(peerPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection on port 8080 to be allowed")
		}

		// Test denied port 80
		allowed, err = networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{portPolicy},
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP(peerPod.Status.PodIP),
			80,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected connection on port 80 to be denied")
		}
	})

	// Test 12: No network policies (default allow)
	t.Run("Should allow all traffic when no network policies are applied", func(t *testing.T) {
		// Test with empty policy list
		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{}, // No policies
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP(peerPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection to be allowed when no policies are present")
		}

		allowed, err = networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{},
			networkingv1.PolicyTypeEgress,
			peerPod,
			net.ParseIP(targetPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected egress connection to be allowed when no policies are present")
		}
	})

	// Test 13: Namespace selector only (no pod selector)
	t.Run("Should handle namespace-only selectors correctly", func(t *testing.T) {
		namespaceOnlyPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-only",
				Namespace: targetPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
						// No PodSelector means all pods in matching namespaces
					}},
				}},
			},
		}

		// Should allow traffic from any pod in a namespace with env=prod
		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{namespaceOnlyPolicy},
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP(peerPod.Status.PodIP), // From peer-namespace with env=prod
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection from prod namespace to be allowed")
		}
	})

	// Test 14: Port ranges
	t.Run("Should handle port ranges correctly", func(t *testing.T) {
		portRangePolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "port-range",
				Namespace: targetPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{
						Port:    &intstr.IntOrString{Type: intstr.Int, IntVal: 8080},
						EndPort: func() *int32 { p := int32(8090); return &p }(), // Port range 8080-8090
					}},
				}},
			},
		}

		// Test port within range
		allowed, err := networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{portRangePolicy},
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP(peerPod.Status.PodIP),
			8085, // Within range 8080-8090
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection on port 8085 (within range) to be allowed")
		}

		// Test port outside range
		allowed, err = networkpolicy.EvaluatePodConnectivity(
			[]*networkingv1.NetworkPolicy{portRangePolicy},
			networkingv1.PolicyTypeIngress,
			targetPod,
			net.ParseIP(peerPod.Status.PodIP),
			9000, // Outside range
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected connection on port 9000 (outside range) to be denied")
		}
	})
}

// TestEndToEndNetworkPolicyValidation tests the core requirement:
// Traffic must be allowed in BOTH source egress AND destination ingress for connection to succeed
func TestEndToEndNetworkPolicyValidation(t *testing.T) {
	// Setup test pods and namespaces
	sourcePod := newPod("client-pod", "client-ns", "10.0.1.5", map[string]string{"app": "client", "role": "frontend"})
	destPod := newPod("api-pod", "api-ns", "10.0.2.10", map[string]string{"app": "api", "role": "backend"})
	
	podsByIP := map[string]*v1.Pod{
		sourcePod.Status.PodIP: sourcePod,
		destPod.Status.PodIP:   destPod,
	}
	namespacesByName := map[string]*v1.Namespace{
		"client-ns": newNamespace("client-ns", map[string]string{"tier": "frontend", "env": "prod"}),
		"api-ns":    newNamespace("api-ns", map[string]string{"tier": "backend", "env": "prod"}),
	}

	t.Run("Should ALLOW when BOTH source egress AND destination ingress allow", func(t *testing.T) {
		// Source egress policy - allows egress to api pods in backend tier
		sourceEgressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "client-egress-allow",
				Namespace: sourcePod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8080}}},
				}},
			},
		}

		// Destination ingress policy - allows ingress from client pods in frontend tier
		destIngressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-ingress-allow",
				Namespace: destPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "frontend"}},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8080}}},
				}},
			},
		}

		// Get source egress policies
		sourceEgressPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(sourcePod, []*networkingv1.NetworkPolicy{sourceEgressPolicy})
		if err != nil {
			t.Fatalf("failed to get source egress policies: %v", err)
		}

		// Get destination ingress policies
		destIngressPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(destPod, []*networkingv1.NetworkPolicy{destIngressPolicy})
		if err != nil {
			t.Fatalf("failed to get destination ingress policies: %v", err)
		}

		// Test egress from source
		egressAllowed, err := networkpolicy.EvaluatePodConnectivity(
			sourceEgressPolicies,
			networkingv1.PolicyTypeEgress,
			sourcePod,
			net.ParseIP(destPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("failed to evaluate egress: %v", err)
		}

		// Test ingress to destination
		ingressAllowed, err := networkpolicy.EvaluatePodConnectivity(
			destIngressPolicies,
			networkingv1.PolicyTypeIngress,
			destPod,
			net.ParseIP(sourcePod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("failed to evaluate ingress: %v", err)
		}

		// Both must be true for connection to succeed
		bothAllowed := egressAllowed && ingressAllowed

		if !bothAllowed {
			t.Fatalf("expected connection to be allowed (egress: %v, ingress: %v), but overall result was denied", egressAllowed, ingressAllowed)
		}
	})

	t.Run("Should DENY when source egress allows but destination ingress denies", func(t *testing.T) {
		// Source egress policy - allows egress to api pods
		sourceEgressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "client-egress-allow",
				Namespace: sourcePod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8080}}},
				}},
			},
		}

		// Destination ingress policy - DENIES ingress (only allows from monitoring pods, not client pods)
		destIngressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-ingress-deny-clients",
				Namespace: destPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "monitoring"}}, // Only monitoring, not client
					}},
				}},
			},
		}

		sourceEgressPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(sourcePod, []*networkingv1.NetworkPolicy{sourceEgressPolicy})
		if err != nil {
			t.Fatalf("failed to get source egress policies: %v", err)
		}

		destIngressPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(destPod, []*networkingv1.NetworkPolicy{destIngressPolicy})
		if err != nil {
			t.Fatalf("failed to get destination ingress policies: %v", err)
		}

		// Test egress from source (should be allowed)
		egressAllowed, err := networkpolicy.EvaluatePodConnectivity(
			sourceEgressPolicies,
			networkingv1.PolicyTypeEgress,
			sourcePod,
			net.ParseIP(destPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("failed to evaluate egress: %v", err)
		}

		// Test ingress to destination (should be denied)
		ingressAllowed, err := networkpolicy.EvaluatePodConnectivity(
			destIngressPolicies,
			networkingv1.PolicyTypeIngress,
			destPod,
			net.ParseIP(sourcePod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("failed to evaluate ingress: %v", err)
		}

		// Connection should be denied because ingress is denied (even though egress is allowed)
		bothAllowed := egressAllowed && ingressAllowed

		if bothAllowed {
			t.Fatalf("expected connection to be denied (egress: %v, ingress: %v), but overall result was allowed", egressAllowed, ingressAllowed)
		}

		// Verify that egress is allowed but ingress is denied
		if !egressAllowed {
			t.Fatal("expected egress to be allowed")
		}
		if ingressAllowed {
			t.Fatal("expected ingress to be denied")
		}
	})

	t.Run("Should DENY when destination ingress allows but source egress denies", func(t *testing.T) {
		// Source egress policy - DENIES egress (only allows to monitoring pods, not api pods)
		sourceEgressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "client-egress-deny-api",
				Namespace: sourcePod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "monitoring"}}, // Only monitoring, not api
					}},
				}},
			},
		}

		// Destination ingress policy - allows ingress from client pods
		destIngressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-ingress-allow-clients",
				Namespace: destPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "frontend"}},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8080}}},
				}},
			},
		}

		sourceEgressPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(sourcePod, []*networkingv1.NetworkPolicy{sourceEgressPolicy})
		if err != nil {
			t.Fatalf("failed to get source egress policies: %v", err)
		}

		destIngressPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(destPod, []*networkingv1.NetworkPolicy{destIngressPolicy})
		if err != nil {
			t.Fatalf("failed to get destination ingress policies: %v", err)
		}

		// Test egress from source (should be denied)
		egressAllowed, err := networkpolicy.EvaluatePodConnectivity(
			sourceEgressPolicies,
			networkingv1.PolicyTypeEgress,
			sourcePod,
			net.ParseIP(destPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("failed to evaluate egress: %v", err)
		}

		// Test ingress to destination (should be allowed)
		ingressAllowed, err := networkpolicy.EvaluatePodConnectivity(
			destIngressPolicies,
			networkingv1.PolicyTypeIngress,
			destPod,
			net.ParseIP(sourcePod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("failed to evaluate ingress: %v", err)
		}

		// Connection should be denied because egress is denied (even though ingress is allowed)
		bothAllowed := egressAllowed && ingressAllowed

		if bothAllowed {
			t.Fatalf("expected connection to be denied (egress: %v, ingress: %v), but overall result was allowed", egressAllowed, ingressAllowed)
		}

		// Verify that ingress is allowed but egress is denied
		if egressAllowed {
			t.Fatal("expected egress to be denied")
		}
		if !ingressAllowed {
			t.Fatal("expected ingress to be allowed")
		}
	})

	t.Run("Should DENY when both source egress AND destination ingress deny", func(t *testing.T) {
		// Source egress policy - denies all egress
		sourceEgressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "client-egress-deny-all",
				Namespace: sourcePod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress:      []networkingv1.NetworkPolicyEgressRule{}, // Empty = deny all
			},
		}

		// Destination ingress policy - denies all ingress
		destIngressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-ingress-deny-all",
				Namespace: destPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{}, // Empty = deny all
			},
		}

		sourceEgressPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(sourcePod, []*networkingv1.NetworkPolicy{sourceEgressPolicy})
		if err != nil {
			t.Fatalf("failed to get source egress policies: %v", err)
		}

		destIngressPolicies, err := networkpolicy.GetLocalNetworkPoliciesForPod(destPod, []*networkingv1.NetworkPolicy{destIngressPolicy})
		if err != nil {
			t.Fatalf("failed to get destination ingress policies: %v", err)
		}

		// Test egress from source (should be denied)
		egressAllowed, err := networkpolicy.EvaluatePodConnectivity(
			sourceEgressPolicies,
			networkingv1.PolicyTypeEgress,
			sourcePod,
			net.ParseIP(destPod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("failed to evaluate egress: %v", err)
		}

		// Test ingress to destination (should be denied)
		ingressAllowed, err := networkpolicy.EvaluatePodConnectivity(
			destIngressPolicies,
			networkingv1.PolicyTypeIngress,
			destPod,
			net.ParseIP(sourcePod.Status.PodIP),
			8080,
			podsByIP,
			namespacesByName,
		)
		if err != nil {
			t.Fatalf("failed to evaluate ingress: %v", err)
		}

		// Both should be denied
		bothAllowed := egressAllowed && ingressAllowed

		if bothAllowed {
			t.Fatalf("expected connection to be denied (egress: %v, ingress: %v), but overall result was allowed", egressAllowed, ingressAllowed)
		}

		// Verify both are denied
		if egressAllowed {
			t.Fatal("expected egress to be denied")
		}
		if ingressAllowed {
			t.Fatal("expected ingress to be denied")
		}
	})
}

// TestEvaluateFullConnectivity tests the comprehensive bidirectional evaluation
func TestEvaluateFullConnectivity(t *testing.T) {
	// Setup test environment
	sourcePod := newPod("client-pod", "frontend", "10.0.1.5", map[string]string{"app": "client", "tier": "web"})
	destPod := newPod("api-pod", "backend", "10.0.2.10", map[string]string{"app": "api", "tier": "service"})
	
	podsByIP := map[string]*v1.Pod{
		sourcePod.Status.PodIP: sourcePod,
		destPod.Status.PodIP:   destPod,
	}
	namespacesByName := map[string]*v1.Namespace{
		"frontend": newNamespace("frontend", map[string]string{"tier": "web", "env": "prod"}),
		"backend":  newNamespace("backend", map[string]string{"tier": "service", "env": "prod"}),
	}

	t.Run("Should ALLOW when both source egress and destination ingress allow", func(t *testing.T) {
		// Source egress policy: allows connection to API pods
		sourceEgressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "client-egress",
				Namespace: sourcePod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To: []networkingv1.NetworkPolicyPeer{{
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "service"}},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{
						Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8080},
					}},
				}},
			},
		}

		// Destination ingress policy: allows connection from client pods
		destIngressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-ingress",
				Namespace: destPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{
						Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8080},
					}},
				}},
			},
		}

		allPolicies := []*networkingv1.NetworkPolicy{sourceEgressPolicy, destIngressPolicy}

		allowed, err := networkpolicy.EvaluateFullConnectivity(
			sourcePod, destPod, 8080, allPolicies, podsByIP, namespacesByName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection to be allowed when both egress and ingress policies allow")
		}
	})

	t.Run("Should DENY when source egress allows but destination ingress denies", func(t *testing.T) {
		// Source egress policy: allows all egress
		sourceEgressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "client-egress-allow",
				Namespace: sourcePod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To: []networkingv1.NetworkPolicyPeer{{
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "service"}},
					}},
				}},
			},
		}

		// Destination ingress policy: denies all ingress (empty rules)
		destIngressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-ingress-deny",
				Namespace: destPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{}, // Empty = deny all
			},
		}

		allPolicies := []*networkingv1.NetworkPolicy{sourceEgressPolicy, destIngressPolicy}

		allowed, err := networkpolicy.EvaluateFullConnectivity(
			sourcePod, destPod, 8080, allPolicies, podsByIP, namespacesByName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected connection to be denied when destination ingress policy denies")
		}
	})

	t.Run("Should DENY when destination ingress allows but source egress denies", func(t *testing.T) {
		// Source egress policy: denies all egress (empty rules)
		sourceEgressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "client-egress-deny",
				Namespace: sourcePod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress:      []networkingv1.NetworkPolicyEgressRule{}, // Empty = deny all
			},
		}

		// Destination ingress policy: allows all ingress from client
		destIngressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-ingress-allow",
				Namespace: destPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
					}},
				}},
			},
		}

		allPolicies := []*networkingv1.NetworkPolicy{sourceEgressPolicy, destIngressPolicy}

		allowed, err := networkpolicy.EvaluateFullConnectivity(
			sourcePod, destPod, 8080, allPolicies, podsByIP, namespacesByName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected connection to be denied when source egress policy denies")
		}
	})

	t.Run("Should ALLOW when no policies apply (default allow)", func(t *testing.T) {
		allPolicies := []*networkingv1.NetworkPolicy{} // No policies

		allowed, err := networkpolicy.EvaluateFullConnectivity(
			sourcePod, destPod, 8080, allPolicies, podsByIP, namespacesByName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected connection to be allowed when no policies apply (default allow)")
		}
	})
}

// TestFilterPoliciesByType verifies that only relevant policies are shown in output
func TestFilterPoliciesByType(t *testing.T) {
	// Create policies with different policy types
	egressOnlyPolicy := newNetworkPolicy("egress-only", "default", labels.Set{"app": "client"}, networkingv1.PolicyTypeEgress)
	ingressOnlyPolicy := newNetworkPolicy("ingress-only", "default", labels.Set{"app": "client"}, networkingv1.PolicyTypeIngress)
	bothTypesPolicy := newNetworkPolicy("both-types", "default", labels.Set{"app": "client"}, networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress)
	
	allPolicies := []*networkingv1.NetworkPolicy{egressOnlyPolicy, ingressOnlyPolicy, bothTypesPolicy}
	
	t.Run("Should filter to only egress policies", func(t *testing.T) {
		filtered := networkpolicy.FilterPoliciesByType(allPolicies, networkingv1.PolicyTypeEgress)
		
		if len(filtered) != 2 {
			t.Fatalf("expected 2 egress policies, got %d", len(filtered))
		}
		
		// Should contain egress-only and both-types
		foundEgressOnly := false
		foundBothTypes := false
		for _, policy := range filtered {
			switch policy.Name {
			case "egress-only":
				foundEgressOnly = true
			case "both-types":
				foundBothTypes = true
			case "ingress-only":
				t.Fatal("ingress-only policy should not be in egress filter")
			}
		}
		
		if !foundEgressOnly || !foundBothTypes {
			t.Fatal("expected to find both egress-only and both-types policies")
		}
	})
	
	t.Run("Should filter to only ingress policies", func(t *testing.T) {
		filtered := networkpolicy.FilterPoliciesByType(allPolicies, networkingv1.PolicyTypeIngress)
		
		if len(filtered) != 2 {
			t.Fatalf("expected 2 ingress policies, got %d", len(filtered))
		}
		
		// Should contain ingress-only and both-types
		foundIngressOnly := false
		foundBothTypes := false
		for _, policy := range filtered {
			switch policy.Name {
			case "ingress-only":
				foundIngressOnly = true
			case "both-types":
				foundBothTypes = true
			case "egress-only":
				t.Fatal("egress-only policy should not be in ingress filter")
			}
		}
		
		if !foundIngressOnly || !foundBothTypes {
			t.Fatal("expected to find both ingress-only and both-types policies")
		}
	})
}
