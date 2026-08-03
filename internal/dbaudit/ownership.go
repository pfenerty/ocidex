// Package dbaudit inspects the live database for state that migrations or the
// application cannot repair themselves — principally object ownership.
//
// Postgres requires ownership for CREATE OR REPLACE FUNCTION, DROP, ALTER
// TABLE and TRUNCATE. An object created out-of-band by a superuser (typically
// hand-run psql on a deployed database) is therefore permanently unusable by
// the application role: every later migration touching it fails, and runtime
// paths that TRUNCATE or ALTER it fail too. Neither a migration nor the app can
// fix that, because ALTER ... OWNER TO also requires ownership. The only
// remedy is a superuser running ALTER, so the job here is to detect the
// condition early and print the exact statements an operator must run.
package dbaudit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Object is a public-schema object not owned by (or by a role granted to) the
// connected role.
type Object struct {
	// Kind is the SQL keyword used in ALTER statements: TABLE, VIEW,
	// MATERIALIZED VIEW, SEQUENCE, FUNCTION, PROCEDURE or AGGREGATE.
	Kind string
	// Name is the object identifier, already quoted and — for routines —
	// carrying its argument list, e.g. `visible_registry_ids(uuid, boolean)`.
	Name string
	// Owner is the role that currently owns the object.
	Owner string
}

// AlterOwnerSQL renders the statement that hands the object to role.
func (o Object) AlterOwnerSQL(role string) string {
	return fmt.Sprintf("ALTER %s public.%s OWNER TO %s;", o.Kind, o.Name, quoteIdent(role))
}

// misownedQuery lists public-schema objects the current role does not own.
//
// pg_has_role(..., 'USAGE') rather than a string compare on the owner name:
// ownership is satisfied by membership in the owning role, so a direct
// comparison would report false positives whenever a group role owns the
// schema. Extension members (pg_depend.deptype = 'e', e.g. the ~30 pg_trgm
// functions) are excluded — they are owned by whoever ran CREATE EXTENSION,
// which is normal and not something an operator should "fix". Indexes are
// excluded because their ownership always follows their table.
const misownedQuery = `
SELECT kind, name, owner FROM (
    SELECT
        CASE c.relkind
            WHEN 'r' THEN 'TABLE'
            WHEN 'p' THEN 'TABLE'
            WHEN 'v' THEN 'VIEW'
            WHEN 'm' THEN 'MATERIALIZED VIEW'
            WHEN 'S' THEN 'SEQUENCE'
        END                              AS kind,
        quote_ident(c.relname)           AS name,
        pg_get_userbyid(c.relowner)      AS owner
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
      AND NOT pg_has_role(current_user, c.relowner, 'USAGE')
      AND NOT EXISTS (
          SELECT 1 FROM pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e')
    UNION ALL
    SELECT
        CASE p.prokind
            WHEN 'p' THEN 'PROCEDURE'
            WHEN 'a' THEN 'AGGREGATE'
            ELSE 'FUNCTION'
        END,
        quote_ident(p.proname) || '(' || pg_get_function_identity_arguments(p.oid) || ')',
        pg_get_userbyid(p.proowner)
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND NOT pg_has_role(current_user, p.proowner, 'USAGE')
      AND NOT EXISTS (
          SELECT 1 FROM pg_depend d
          WHERE d.classid = 'pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e')
) o
ORDER BY kind, name`

// Misowned returns every public-schema object the connected role cannot own,
// ordered by kind then name. An empty slice means the schema is consistent.
func Misowned(ctx context.Context, conn *sql.DB) ([]Object, error) {
	rows, err := conn.QueryContext(ctx, misownedQuery)
	if err != nil {
		return nil, fmt.Errorf("querying object ownership: %w", err)
	}
	defer rows.Close()

	var objs []Object
	for rows.Next() {
		var o Object
		if err := rows.Scan(&o.Kind, &o.Name, &o.Owner); err != nil {
			return nil, fmt.Errorf("scanning object ownership: %w", err)
		}
		objs = append(objs, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading object ownership: %w", err)
	}
	return objs, nil
}

// CurrentUser reports the role the connection authenticated as.
func CurrentUser(ctx context.Context, conn *sql.DB) (string, error) {
	var role string
	if err := conn.QueryRowContext(ctx, "SELECT current_user").Scan(&role); err != nil {
		return "", fmt.Errorf("querying current_user: %w", err)
	}
	return role, nil
}

// Report renders operator-facing remediation for objs. It is written to be
// pasted into a superuser psql session verbatim.
func Report(objs []Object, role string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d public-schema object(s) are not owned by %q:\n", len(objs), role)
	for _, o := range objs {
		fmt.Fprintf(&b, "  %-18s public.%s (owner: %s)\n", o.Kind, o.Name, o.Owner)
	}
	b.WriteString("\nThese were created out-of-band, not by a migration. Ownership is required\n")
	b.WriteString("for CREATE OR REPLACE, DROP, ALTER and TRUNCATE, so migrations and runtime\n")
	b.WriteString("paths touching them will fail. Fix as a superuser:\n\n")
	for _, o := range objs {
		fmt.Fprintf(&b, "  %s\n", o.AlterOwnerSQL(role))
	}
	return b.String()
}

// quoteIdent double-quotes an identifier if it is not already safe to use bare.
func quoteIdent(s string) string {
	safe := s != ""
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r == '_':
		case (r >= '0' && r <= '9') && i > 0:
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
