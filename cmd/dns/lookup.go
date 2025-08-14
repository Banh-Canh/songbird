package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	k8sutils "github.com/Banh-Canh/songbird/internal/k8s/k8sutils"
	"github.com/Banh-Canh/songbird/internal/utils/logger"
)

var lookupCmd = &cobra.Command{
	Use:   "lookup <domain-name>",
	Short: "Executes a DNS lookup against CoreDNS using port-forward",
	Long: `Executes a DNS lookup for a given domain name by port-forwarding to a CoreDNS pod.
This subcommand helps to debug DNS resolution issues within the Kubernetes cluster.

Example:

songbird dns lookup kubernetes.default
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domainName := args[0]

		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			logger.Logger.Error("failed to load kubeconfig", slog.Any("error", err))
			return
		}
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			logger.Logger.Error("failed to create k8s client", slog.Any("error", err))
			return
		}
		ctx := context.Background()

		logger.Logger.Debug("searching for a CoreDNS pod in kube-system namespace...")
		pods, err := clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=kube-dns",
		})
		if err != nil {
			logger.Logger.Error("failed to list CoreDNS pods", slog.Any("error", err))
			return
		}

		if len(pods.Items) == 0 {
			logger.Logger.Error("no CoreDNS pods found with label 'k8s-app=kube-dns'")
			return
		}

		corednsPod := &pods.Items[0]
		logger.Logger.Debug(fmt.Sprintf("found CoreDNS pod: %s", corednsPod.Name))

		localPort := 10053
		targetPort := 53

		logger.Logger.Debug(fmt.Sprintf("starting port-forward to pod: %s on local port %d...", corednsPod.Name, localPort))
		_, stopChan, err := k8sutils.RunPortForward(ctx, config, corednsPod, localPort, targetPort)
		if err != nil {
			logger.Logger.Error("failed to start port-forward", slog.Any("error", err))
			return
		}
		defer close(stopChan)

		clusterDomain, err := k8sutils.GetClusterDomain(ctx, clientset)
		if err != nil {
			logger.Logger.Error("failed to get cluster domain, using default 'cluster.local'", slog.Any("error", err))
			clusterDomain = "cluster.local"
		}

		// List of domain names to try, in order
		domainsToTry := []string{
			domainName,
			fmt.Sprintf("%s.default.svc.%s", domainName, clusterDomain),
			fmt.Sprintf("%s.svc.%s", domainName, clusterDomain),
			fmt.Sprintf("%s.%s", domainName, clusterDomain),
			domainName,
		}

		dnsClient := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 10,
				}
				return d.DialContext(ctx, "tcp", "127.0.0.1:"+fmt.Sprintf("%d", localPort))
			},
		}

		for _, targetDomain := range domainsToTry {
			logger.Logger.Debug(fmt.Sprintf("Attempting DNS lookup for '%s'", targetDomain))
			ips, err := dnsClient.LookupHost(ctx, targetDomain)
			if err == nil {
				for _, ip := range ips {
					fmt.Printf("Name:    %s\n", targetDomain)
					fmt.Printf("Address: %s\n", ip)
				}
				return
			}
			logger.Logger.Debug(fmt.Sprintf("DNS lookup for '%s' failed: %v", targetDomain, err))
		}

		logger.Logger.Error("DNS lookup failed for all attempted domains", slog.String("original_domain", domainName))
	},
}

func init() {
	dnsCmd.AddCommand(lookupCmd)
}
