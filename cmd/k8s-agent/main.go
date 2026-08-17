// Command k8s-agent reports the container images running in a Kubernetes
// cluster to OCIDex.
//
// It runs *inside the cluster it reports on* (ADR-044 K1/K2): push, not pull, so
// OCIDex needs no network path to the cluster and no stored kubeconfig. Each
// report is a complete snapshot — everything currently running — because the
// server treats a snapshot as a full replacement (ADR-044 K7). Sending a partial
// list would delete whatever was omitted.
//
// Per ADR-027 the binary works both as a long-lived Deployment and, with --once,
// as a one-shot Job: a single snapshot, then exit 0 on success or 1 on failure.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/health"
	"github.com/pfenerty/ocidex/pkg/client"
)

// podListPageSize bounds one List call. A cluster with tens of thousands of pods
// would otherwise materialise every pod in a single response.
const podListPageSize = 500

func main() {
	if err := run(); err != nil {
		slog.Error("k8s-agent failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	once := flag.Bool("once", false, "Push a single inventory snapshot and exit (K8s Job mode)")
	flag.Parse()

	cfg, err := config.LoadK8sAgent()
	if err != nil {
		return err
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.SlogLevel()})))
	slog.Info("starting k8s-agent",
		"environment", cfg.Environment,
		"once", *once,
		"cluster_id", cfg.ClusterID,
		"server", cfg.ServerURL,
		"namespaces", cfg.Namespaces,
		"interval", cfg.ReportInterval,
	)

	restCfg, err := ctrlconfig.GetConfig()
	if err != nil {
		return fmt.Errorf("loading kubernetes config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("building kubernetes client: %w", err)
	}

	a := &agent{
		cfg:  cfg,
		pods: clientset.CoreV1(),
		api:  client.New(client.Config{BaseURL: cfg.ServerURL, APIKey: cfg.APIKey}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *once {
		if err := a.report(ctx); err != nil {
			return err
		}
		slog.Info("k8s-agent completed", "mode", "once")
		return nil
	}

	healthSrv := health.New(cfg.HealthAddr, nil, nil, slog.Default())
	healthSrv.Start()
	defer healthSrv.Stop()

	// Report immediately rather than waiting out the first interval: on a fresh
	// deployment the cluster would otherwise appear to have never reported, which
	// is the same signal as a dead agent (K2).
	if err := a.report(ctx); err != nil {
		slog.Error("initial inventory report failed", "err", err)
	}

	ticker := time.NewTicker(cfg.ReportInterval)
	defer ticker.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			// A failed push is logged and retried on the next tick, not fatal: the
			// API being briefly unavailable is not a reason to restart the agent,
			// and the server's own last_seen_at staleness is what surfaces a
			// persistently failing one.
			if err := a.report(ctx); err != nil {
				slog.Error("inventory report failed", "err", err)
			}
		case sig := <-quit:
			slog.Info("shutdown signal received", "signal", sig)
			return nil
		}
	}
}

// podLister is the slice of the typed client the agent uses, named so tests can
// substitute a fixture without a live API server.
type podLister interface {
	Pods(namespace string) typedcorev1.PodInterface
}

type agent struct {
	cfg  *config.K8sAgentConfig
	pods podLister
	api  client.Client
}

// report collects one snapshot and pushes it.
func (a *agent) report(ctx context.Context) error {
	start := time.Now()

	pods, err := a.listPods(ctx)
	if err != nil {
		return fmt.Errorf("listing pods: %w", err)
	}
	workloads := buildSnapshot(pods)

	out, err := a.api.PutInventory(ctx, a.cfg.ClusterID, workloads)
	if err != nil {
		return fmt.Errorf("pushing inventory: %w", err)
	}

	slog.Info("inventory reported",
		"pods", len(pods),
		"workloads", len(workloads),
		"unresolvable", countUnresolvable(workloads),
		"accepted", out.Accepted,
		"pruned", out.Pruned,
		"duration", time.Since(start).String(),
	)
	return nil
}

// listPods reads every pod the agent is scoped to. With no namespace allowlist it
// lists across all namespaces in one paged call; with one, it lists each named
// namespace, so a missing namespace is a per-namespace warning rather than a
// failure of the whole snapshot.
func (a *agent) listPods(ctx context.Context) ([]corev1.Pod, error) {
	if len(a.cfg.Namespaces) == 0 {
		return a.listNamespace(ctx, metav1.NamespaceAll)
	}

	var all []corev1.Pod
	for _, ns := range a.cfg.Namespaces {
		pods, err := a.listNamespace(ctx, ns)
		if err != nil {
			// Partial data is the right answer here, but only because the omission
			// is logged: a snapshot missing a namespace prunes that namespace's
			// rows, so this warning is what explains an inventory that shrank.
			slog.Warn("skipping namespace", "namespace", ns, "err", err)
			continue
		}
		all = append(all, pods...)
	}
	return all, nil
}

func (a *agent) listNamespace(ctx context.Context, ns string) ([]corev1.Pod, error) {
	var out []corev1.Pod
	opts := metav1.ListOptions{Limit: podListPageSize}
	for {
		list, err := a.pods.Pods(ns).List(ctx, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, list.Items...)
		if list.Continue == "" {
			return out, nil
		}
		opts.Continue = list.Continue
	}
}
