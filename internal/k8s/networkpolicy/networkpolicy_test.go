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

// Test for EvaluatePodConnectivity
func TestEvaluatePodConnectivity(t *testing.T) {
	// Setup pods and namespaces for the test scenarios
	targetPod := newPod("target-pod", "target-namespace", "10.0.0.10", map[string]string{"app": "api"})
	peerPod := newPod("peer-pod", "peer-namespace", "10.0.0.5", map[string]string{"app": "client"})
	podsByIP := map[string]*v1.Pod{
		targetPod.Status.PodIP: targetPod,
		peerPod.Status.PodIP:   peerPod,
	}
	namespacesByName := map[string]*v1.Namespace{
		"peer-namespace":   newNamespace("peer-namespace", map[string]string{"env": "prod"}),
		"target-namespace": newNamespace("target-namespace", map[string]string{"kubernetes.io/metadata.name": targetPod.Namespace}),
	}

	t.Run("Ingress: should allow connection if a policy explicitly allows it", func(t *testing.T) {
		ingressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: peerPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{MatchLabels: targetPod.Labels},
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"kubernetes.io/metadata.name": targetPod.Namespace,
									},
								},
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

	t.Run("Ingress: should deny connection if no policy allows it", func(t *testing.T) {
		ingressPolicy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: peerPod.Namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{PodSelector: &metav1.LabelSelector{MatchLabels: labels.Set{"app": "non-matching-app"}}},
						},
					},
				},
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
		if allowed {
			t.Fatal("expected connection to be denied, but it was allowed")
		}
	})

	t.Run("Egress: should allow connection if a policy explicitly allows it", func(t *testing.T) {
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
								PodSelector: &metav1.LabelSelector{MatchLabels: targetPod.Labels},
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"kubernetes.io/metadata.name": targetPod.Namespace,
									},
								},
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
}
