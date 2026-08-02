package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

// jobStates is the server's vocabulary, repeated here only to reject a typo
// before it becomes a request that silently returns everything.
var jobStates = []string{"queued", "running", "succeeded", "failed"}

func newJobCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "job",
		Aliases: []string{"jobs"},
		Short:   "Inspect the registry scan queue",
		Long: `Inspect the registry scan queue.

A job is one attempt to pull an image and catalog it. Jobs are created by the
scanner, not by this CLI; what you can do here is watch them and, as an admin,
put a failed one back in the queue.`,
	}
	cmd.AddCommand(newJobListCmd(cfg), newJobGetCmd(cfg), newJobRetryCmd(cfg))
	return cmd
}

func jobColumns() []output.Column[client.ScanJobResponse] {
	return []output.Column[client.ScanJobResponse]{
		{Header: "ID", Value: func(j client.ScanJobResponse) string { return j.Id }},
		{Header: "STATE", Value: func(j client.ScanJobResponse) string { return string(j.State) }},
		{Header: "REPOSITORY", Value: func(j client.ScanJobResponse) string { return j.Repository }},
		{Header: "TAG", Value: func(j client.ScanJobResponse) string { return deref(j.Tag) }},
		{Header: "ATTEMPTS", Value: func(j client.ScanJobResponse) string { return fmt.Sprint(j.Attempts) }},
		{Header: "CREATED", Value: func(j client.ScanJobResponse) string { return j.CreatedAt }},
	}
}

func newJobListCmd(cfg *rootConfig) *cobra.Command {
	var filter client.JobFilter
	var limit, offset int32

	cmd := &cobra.Command{
		Use:   verbList,
		Short: "List scan jobs",
		Long: `List scan jobs, newest first.

Without --state this lists every state, including the succeeded jobs that make
up most of the queue's history. --state failed is the one worth watching.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateJobState(filter.State); err != nil {
				return err
			}
			page, err := cfg.api.ListJobs(cmd.Context(), filter, client.PageOpts{Limit: limit, Offset: offset})
			if err != nil {
				return fmt.Errorf("listing jobs: %w", err)
			}
			if err := output.List(cmd.OutOrStdout(), cfg.format, page.Data, jobColumns()...); err != nil {
				return err
			}
			printPageHint(cmd, cfg, len(page.Data), offset, page.Pagination.Total)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&filter.State, "state", "", "filter by state: queued, running, succeeded, or failed")
	f.Int32Var(&limit, "limit", 0, "maximum jobs to return (server default 50)")
	f.Int32Var(&offset, "offset", 0, "index of the first job to return")
	return cmd
}

// validateJobState rejects an unknown state here rather than sending it: the
// server ignores a state it does not recognise, so the user would get a full
// unfiltered listing and no indication their filter was discarded.
func validateJobState(state string) error {
	if state == "" {
		return nil
	}
	for _, s := range jobStates {
		if state == s {
			return nil
		}
	}
	return usagef("--state must be one of queued, running, succeeded, failed (got %q)", state)
}

func newJobGetCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   verbGet,
		Short: "Show one scan job in full",
		Long: `Show one scan job in full.

The fields that matter on a failure are LAST ERROR and ATTEMPTS: the queue
retries on its own, so a job with several attempts and a stable error is stuck
rather than merely slow.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			job, err := cfg.api.GetJob(cmd.Context(), args[0])
			if err != nil {
				return fmt.Errorf("getting job: %w", err)
			}
			if cfg.format != output.Table {
				return output.Item(cmd.OutOrStdout(), cfg.format, job)
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, job, jobDetailColumns()...)
		},
	}
}

func jobDetailColumns() []output.Column[client.ScanJobResponse] {
	return append(jobColumns(),
		output.Column[client.ScanJobResponse]{Header: "DIGEST", Value: func(j client.ScanJobResponse) string { return j.Digest }},
		output.Column[client.ScanJobResponse]{Header: "REGISTRY", Value: func(j client.ScanJobResponse) string { return deref(j.RegistryId) }},
		output.Column[client.ScanJobResponse]{Header: colSBOM, Value: func(j client.ScanJobResponse) string { return deref(j.SbomId) }},
		output.Column[client.ScanJobResponse]{Header: "WORKER", Value: func(j client.ScanJobResponse) string { return deref(j.WorkerId) }},
		output.Column[client.ScanJobResponse]{Header: "STARTED", Value: func(j client.ScanJobResponse) string { return deref(j.StartedAt) }},
		output.Column[client.ScanJobResponse]{Header: "FINISHED", Value: func(j client.ScanJobResponse) string { return deref(j.FinishedAt) }},
		output.Column[client.ScanJobResponse]{Header: "LAST ERROR", Value: func(j client.ScanJobResponse) string { return deref(j.LastError) }},
	)
}

func newJobRetryCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "retry <id>",
		Short: "Put a failed scan job back in the queue",
		Long: `Put a failed scan job back in the queue.

Admin-only. The server returns no body, so success is silent; re-run
` + "`job get <id>`" + ` to see the job back in the queued state.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := cfg.authed()
			if err != nil {
				return err
			}
			if err := api.RetryJob(cmd.Context(), args[0]); err != nil {
				return fmt.Errorf("retrying job: %w", err)
			}
			// Table mode only, and stderr: a caller scripting this wants the
			// exit code, not a line to strip.
			if cfg.format == output.Table {
				fmt.Fprintf(cmd.ErrOrStderr(), "job %s requeued\n", args[0])
			}
			return nil
		},
	}
}
