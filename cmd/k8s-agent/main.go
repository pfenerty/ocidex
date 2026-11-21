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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/health"
	"github.com/pfenerty/ocidex/internal/metrics"
	"github.com/pfenerty/ocidex/internal/tracing"
	"github.com/pfenerty/ocidex/internal/version"
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

	slog.SetDefault(slog.New(tracing.LogHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.SlogLevel()}))))
	slog.Info("starting k8s-agent",
		"environment", cfg.Environment,
		"once", *once,
		"cluster_id", cfg.ClusterID,
		"server", cfg.ServerURL,
		"namespaces", cfg.Namespaces,
		"interval", cfg.ReportInterval,
		"version", version.String(),
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
		cfg:       cfg,
		pods:      clientset.CoreV1(),
		discovery: clientset.Discovery(),
		api:       client.New(client.Config{BaseURL: cfg.ServerURL, APIKey: cfg.APIKey}),
		oneShot:   *once,
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

	_, stopTracing := tracing.Start(ctx, "ocidex-k8s-agent")
	defer stopTracing()
	mp, metricsHandler, stopMetrics := metrics.Start(ctx, "ocidex-k8s-agent")
	defer stopMetrics()
	if c, err := metrics.Meter(mp).Int64Counter("ocidex.agent.pushes",
		metric.WithDescription("Inventory pushes by outcome (accepted, rejected, failed) and HTTP status.")); err != nil {
		slog.Error("push metric disabled", "err", err)
	} else {
		a.pushes = c
	}
	healthSrv := health.New(cfg.HealthAddr, nil, nil, slog.Default()).WithMetrics(metricsHandler)
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
	cfg       *config.K8sAgentConfig
	pods      podLister
	discovery discovery.ServerVersionInterface
	api       client.Client
	// oneShot reports a zero interval: a --once Job has no next report, and
	// the server must not judge it stale against the default interval.
	oneShot bool
	// pushes counts pushes by outcome; nil in --once mode and in tests.
	pushes metric.Int64Counter
}

// report collects one snapshot and pushes it.
func (a *agent) report(ctx context.Context) error {
	start := time.Now()

	pods, err := a.listPods(ctx)
	if err != nil {
		return fmt.Errorf("listing pods: %w", err)
	}
	workloads := buildSnapshot(pods)

	out, err := a.api.PutInventory(ctx, a.cfg.ClusterID, workloads, a.describe(ctx, pods))
	if err != nil {
		a.countPush(ctx, err)
		var apiErr *client.APIError
		if errors.As(err, &apiErr) {
			// The server's reason is the actionable part — a revoked key, a
			// missing capability, a schema failure — so it is logged as its
			// own field rather than buried in the error string. The server
			// also records it against the cluster.
			slog.ErrorContext(ctx, "inventory push rejected",
				"status", apiErr.Status, "reason", apiErr.Detail, "cluster_id", a.cfg.ClusterID)
		}
		return fmt.Errorf("pushing inventory: %w", err)
	}
	a.countPush(ctx, nil)
	if out.VersionSkew != nil && *out.VersionSkew != "" {
		slog.Warn("agent and server versions differ", "detail", *out.VersionSkew)
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

// countPush records one push outcome: accepted, rejected (the server answered
// with an error status) or failed (no answer).
func (a *agent) countPush(ctx context.Context, err error) {
	if a.pushes == nil {
		return
	}
	outcome, status := "accepted", 200
	var apiErr *client.APIError
	switch {
	case err == nil:
	case errors.As(err, &apiErr):
		outcome, status = "rejected", apiErr.Status
	default:
		outcome, status = "failed", 0
	}
	a.pushes.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome), attribute.Int("status", status)))
}

// describe is the agent's self-report sent with each snapshot.
// Every field is best effort: a discovery failure costs the Kubernetes version,
// not the snapshot.
func (a *agent) describe(ctx context.Context, pods []corev1.Pod) *client.InventoryAgent {
	agentVersion, _, _ := version.Info()
	interval := int32(min(a.cfg.ReportInterval/time.Second, math.MaxInt32)) //nolint:gosec // clamped above
	if a.oneShot {
		interval = 0
	}
	nodes := countNodes(pods)
	namespaces := a.cfg.Namespaces
	if namespaces == nil {
		namespaces = []string{}
	}
	info := &client.InventoryAgent{
		Version:               &agentVersion,
		NodeCount:             &nodes,
		Namespaces:            &namespaces,
		ReportIntervalSeconds: &interval,
		PodName:               optString(a.cfg.PodName),
		PodNamespace:          optString(a.cfg.PodNamespace),
	}
	if a.discovery != nil {
		if v, err := a.discovery.ServerVersion(); err != nil {
			slog.WarnContext(ctx, "reading kubernetes server version", "err", err)
		} else {
			info.KubernetesVersion = &v.GitVersion
		}
	}
	return info
}

// countNodes counts the distinct nodes the pods are scheduled on. It reads the
// pods rather than listing nodes, so the agent needs no RBAC on nodes; with a
// namespace allowlist it is the nodes running those namespaces' pods.
func countNodes(pods []corev1.Pod) int32 {
	seen := map[string]struct{}{}
	for i := range pods {
		if n := pods[i].Spec.NodeName; n != "" {
			seen[n] = struct{}{}
		}
	}
	return int32(len(seen)) //nolint:gosec // bounded by the cluster's node count
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
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
