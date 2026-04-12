// Query helpers for the gin_service fixture. Takes a tainted argument
// and passes it into a SQL execute sink via string concatenation.
// Cross-file taint analysis (issue #46) detects the flow from
// handlers.go search() → runQuery(name) → db.Query.

package gin_service

import "database/sql"

var db *sql.DB

func runQuery(name string) []any {
	// Would become a go/taint-sql-injection finding after #46 when
	// called from handlers.go with a tainted query string.
	_, _ = db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	return nil
}
