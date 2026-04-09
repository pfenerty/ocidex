package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

func main() {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Println("connect err:", err)
		return
	}
	defer conn.Close(ctx)

	fmt.Println("=== SBOM registry_id distribution ===")
	rows, _ := conn.Query(ctx, "SELECT registry_id, COUNT(*) FROM sbom GROUP BY registry_id ORDER BY 2 DESC")
	for rows.Next() {
		var rid any
		var cnt int64
		_ = rows.Scan(&rid, &cnt)
		fmt.Printf("  registry_id=%v count=%d\n", rid, cnt)
	}
	rows.Close()

	fmt.Println("\n=== Registries ===")
	rows2, _ := conn.Query(ctx, "SELECT id, name, url, visibility FROM registry")
	for rows2.Next() {
		var id, name, url, vis string
		_ = rows2.Scan(&id, &name, &url, &vis)
		fmt.Printf("  id=%s name=%s url=%s visibility=%s\n", id, name, url, vis)
	}
	rows2.Close()

	fmt.Println("\n=== Migration check ===")
	var exists bool
	_ = conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_proc WHERE proname = 'sbom_visible')").Scan(&exists)
	fmt.Printf("  sbom_visible function exists: %v\n", exists)

	fmt.Println("\n=== Sample artifacts ===")
	rows3, _ := conn.Query(ctx, "SELECT a.id, a.name, a.type FROM artifact a LIMIT 10")
	for rows3.Next() {
		var id, name, typ string
		_ = rows3.Scan(&id, &name, &typ)
		fmt.Printf("  id=%s name=%s type=%s\n", id, name, typ)
	}
	rows3.Close()
}
