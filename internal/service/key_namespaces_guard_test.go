package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryVisibilityQuerySetsKeyNamespaces enforces ADR-0058 A2 at the Go
// call sites. Every query that applies row visibility takes the key's
// namespace set, and a nil set means "no narrowing". So a call site that
// forgets the field compiles, runs, and silently lets a namespace-scoped key
// read outside its namespaces. This test finds every composite literal of a
// repository params type that has a KeyNamespaces field and fails unless the
// literal names it, even if only to pass nil on purpose.
func TestEveryVisibilityQuerySetsKeyNamespaces(t *testing.T) {
	scoped := scopedParamTypes(t, filepath.Join("..", "repository"))
	if len(scoped) == 0 {
		t.Fatal("no repository params type has a KeyNamespaces field; the guard is looking in the wrong place")
	}

	var missing []string
	for _, dir := range []string{".", filepath.Join("..", "api"), filepath.Join("..", "worker"), filepath.Join("..", "enrichment")} {
		walkGoFiles(t, dir, func(fset *token.FileSet, f *ast.File) {
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || !scoped[sel.Sel.Name] {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "repository" {
					return true
				}
				for _, e := range lit.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "KeyNamespaces" {
							return true
						}
					}
				}
				missing = append(missing, fset.Position(lit.Pos()).String()+" repository."+sel.Sel.Name)
				return true
			})
		})
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s does not set KeyNamespaces (pass the caller's vis.keyNamespaces(), or nil with a comment saying why)", m)
	}
}

// scopedParamTypes returns the names of the struct types in dir that have a
// KeyNamespaces field: the generated params of every visibility-scoped query.
func scopedParamTypes(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	walkGoFiles(t, dir, func(_ *token.FileSet, f *ast.File) {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, s := range gd.Specs {
				ts := s.(*ast.TypeSpec)
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, fld := range st.Fields.List {
					for _, n := range fld.Names {
						if n.Name == "KeyNamespaces" {
							out[ts.Name.Name] = true
						}
					}
				}
			}
		}
	})
	return out
}

// walkGoFiles parses every non-test Go file under dir.
func walkGoFiles(t *testing.T, dir string, fn func(*token.FileSet, *ast.File)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		fn(fset, f)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walking %s: %v", dir, err)
	}
}

// TestNoQueryUsesUnscopedVisibility is the SQL half of the guard: a visibility
// function called with a viewer but without the key's namespace set
// (ADR-0058 A2) would let a scoped key read everything its holder can. Calls
// with no viewer at all (the anonymous, public-only reads) are exempt.
func TestNoQueryUsesUnscopedVisibility(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "db", "queries", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no query files found: %v", err)
	}
	funcs := []string{"visible_namespace_ids(", "artifact_visible(", "sbom_visible(", "owned_namespace_ids("}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// Comments mention the functions by name; only code counts.
		var code strings.Builder
		for _, line := range strings.Split(string(raw), "\n") {
			if i := strings.Index(line, "--"); i >= 0 {
				line = line[:i]
			}
			code.WriteString(line + "\n")
		}
		src := code.String()
		for _, fn := range funcs {
			for i := strings.Index(src, fn); i >= 0; {
				args := callArgs(src[i+len(fn):])
				viewer := strings.Contains(args, "user_id") || strings.Contains(args, "viewer_id")
				if viewer && !strings.Contains(args, "key_namespaces") {
					t.Errorf("%s: %s%s) passes a viewer but not sqlc.narg('key_namespaces')", filepath.Base(f), fn, args)
				}
				next := strings.Index(src[i+1:], fn)
				if next < 0 {
					break
				}
				i += 1 + next
			}
		}
	}
}

// callArgs returns the text up to the parenthesis that closes the call whose
// arguments s begins with.
func callArgs(s string) string {
	depth := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return s[:i]
			}
			depth--
		}
	}
	return s
}
