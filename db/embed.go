// Package db provides embedded database migration files.
package db

import "embed"

// Migrations contains the embedded SQL migration files.
//
//go:embed migrations/*.sql
var Migrations embed.FS
