// Package main is the entry point for the OCIDex K8s operator.
// It manages OCIRegistry, ScanRequest, and APIKey custom resources.
//
// Required env vars: OCIDEX_SERVER, OCIDEX_API_KEY, OPERATOR_NAMESPACE.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	ocidexv1alpha1 "github.com/pfenerty/ocidex/api/v1alpha1"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/controller"
	"github.com/pfenerty/ocidex/pkg/client"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ocidexv1alpha1.AddToScheme(scheme))
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	metricsAddr := flag.String("metrics-bind-address", ":8080", "Address for the metrics endpoint")
	probeAddr := flag.String("health-probe-bind-address", ":8081", "Address for health and readiness probes")
	leaderElect := flag.Bool("leader-elect", false, "Enable leader election (required when running multiple replicas)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.SlogLevel(),
	})))

	serverURL := os.Getenv("OCIDEX_SERVER")
	apiKey := os.Getenv("OCIDEX_API_KEY")
	if serverURL == "" || apiKey == "" {
		return fmt.Errorf("OCIDEX_SERVER and OCIDEX_API_KEY must be set")
	}

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	if operatorNS == "" {
		return fmt.Errorf("OPERATOR_NAMESPACE must be set")
	}

	ocidexClient := client.New(client.Config{BaseURL: serverURL, APIKey: apiKey})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: *metricsAddr},
		HealthProbeBindAddress:  *probeAddr,
		LeaderElection:          *leaderElect,
		LeaderElectionID:        "ocidex-operator-leader",
		LeaderElectionNamespace: operatorNS,
	})
	if err != nil {
		return fmt.Errorf("creating manager: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("setting up healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("setting up readyz: %w", err)
	}

	if err := (&controller.OCIRegistryReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		OCIDexClient: ocidexClient,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setting up OCIRegistry controller: %w", err)
	}

	// ScanRequest and APIKey controllers registered in ocidex-01v.4 and ocidex-01v.5.

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	slog.Info("starting operator manager",
		"environment", cfg.Environment,
		"ocidex_server", serverURL,
		"leader_elect", *leaderElect,
	)
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("running manager: %w", err)
	}
	return nil
}
