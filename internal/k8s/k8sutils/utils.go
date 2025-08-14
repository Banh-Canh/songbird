package k8sutils

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// getClusterDomain fetches the cluster domain from the CoreDNS ConfigMap.
func GetClusterDomain(ctx context.Context, clientset *kubernetes.Clientset) (string, error) {
	configMap, err := clientset.CoreV1().ConfigMaps("kube-system").Get(ctx, "coredns", metav1.GetOptions{})
	if err != nil {
		configMap, err = clientset.CoreV1().ConfigMaps("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to get coredns configmap: %w", err)
		}
	}

	corefile, ok := configMap.Data["Corefile"]
	if !ok {
		return "", fmt.Errorf("corefile not found in coredns configmap")
	}

	lines := strings.SplitSeq(corefile, "\n")
	for line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "kubernetes") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 2 {
				domain := parts[1]
				if strings.Contains(domain, ".") {
					return domain, nil
				}
			}
		}
	}

	return "cluster.local", nil
}
