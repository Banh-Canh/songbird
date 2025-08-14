package k8sutils

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/Banh-Canh/songbird/internal/utils/logger"
)

// logWriter is an io.Writer that logs output at a specific slog level, i'm using it to hide the portforward function output behind logs
type logWriter struct {
	logger *slog.Logger
	level  slog.Level
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	lw.logger.Log(context.Background(), lw.level, strings.TrimSpace(string(p)))
	return len(p), nil
}

// runPortForward sets up and runs the port-forwarding process using client-go.
func RunPortForward(
	ctx context.Context,
	restConfig *rest.Config,
	pod *corev1.Pod,
	localPort, targetPort int,
) (*portforward.PortForwarder, chan struct{}, error) {
	// required for the port-forwarding connection.
	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create round tripper: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create k8s client: %w", err)
	}

	// The port-forwarding process is initiated by sending a request to this endpoint.
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(pod.Namespace).
		Name(pod.Name).
		SubResource("portforward")

	// stopChan is a channel used to signal the port-forwarder to stop.
	// Closing this channel will terminate the port-forwarding process.
	stopChan := make(chan struct{}, 1)

	// readyChan is a channel used to signal when the port-forwarding connection
	readyChan := make(chan struct{})

	// hiding ugly output in logs !
	out := &logWriter{logger: logger.Logger, level: slog.LevelDebug}
	errOut := &logWriter{logger: logger.Logger, level: slog.LevelError}

	// necessary for the bidirectional communication of port forwarding
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", req.URL())

	fw, err := portforward.New(dialer, []string{fmt.Sprintf("%d:%d", localPort, targetPort)}, stopChan, readyChan, out, errOut)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create port-forwarder: %w", err)
	}

	// This is where the actual port-forwarding process begins. It's started in a
	// separate goroutine so it doesn't block the current function. Because I want to run a dns lookup after it.
	go func() {
		if err = fw.ForwardPorts(); err != nil {
			logger.Logger.Error("failed to forward ports", slog.Any("error", err))
		}
	}()

	select {
	case <-readyChan:
		// If the port-forward is ready, the function returns the PortForwarder and the stop channel.
		return fw, stopChan, nil
	case <-time.After(30 * time.Second):
		// If a timeout occurs, the stop channel is closed to terminate the process,
		// and an error is returned.
		close(stopChan)
		return nil, nil, fmt.Errorf("timeout waiting for port-forward to become ready")
	case <-ctx.Done():
		// If the context is canceled, the stop channel is closed and the context error is returned.
		close(stopChan)
		return nil, nil, ctx.Err()
	}
}
