package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

// deletable is what a delete command needs once the reference the user typed
// has been resolved: the id to send, and the sentence to confirm before
// sending it.
type deletable struct {
	id     string
	prompt string
}

// newDeleteCmd builds the `delete` command shared by every noun whose deletes
// differ only in what they resolve and what they call. Keeping one
// implementation is what makes the confirmation, the --yes escape hatch, and
// the "deleted <id>" line identical across nouns — a script that handles one
// handles all of them.
func newDeleteCmd(
	use, short, noun string,
	resolve func(ctx context.Context, ref string) (deletable, error),
	del func(ctx context.Context, id string) error,
) *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolve(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := confirm(cmd, yes, target.prompt); err != nil {
				return err
			}
			if err := del(cmd.Context(), target.id); err != nil {
				return fmt.Errorf("deleting %s: %w", noun, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted %s\n", target.id)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not prompt for confirmation")
	return cmd
}
