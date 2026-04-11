// Negative fixtures for the Go taint engine. Every call site below
// would match a conservative go/no-* rule's surface, but no
// go/taint-* rule may fire: the sinks either take literal arguments,
// a value that had its taint cleared by reassignment, or a value
// that lives in a sibling function (cross-function isolation).
package main

import (
	"database/sql"
	"fmt"
	"html"
	"net/http"
	"os/exec"
)

// 1. Static literal argument — no taint source at all.
func staticExec() {
	exec.Command("ls", "-la")
}

// 2. Reassignment to a literal kills the taint.
func reassignKillsTaint(c *gin.Context) {
	cmd := c.Query("cmd")
	cmd = "echo hello"
	exec.Command(cmd)
}

// 3. Cross-function isolation: the source lives in one function,
//    the sink in another — no interprocedural flow through a
//    global.
var stashed string

func stash(c *gin.Context) {
	stashed = c.Query("cmd")
}

func useStashed() {
	// stashed is not tracked by the intraprocedural engine.
	exec.Command(stashed)
}

// 4. Sanitized flow: html.EscapeString is a declared sanitizer in
//    the unit tests, but outside a spec that lists it we instead
//    just show that passing through a conversion is fine because
//    the sink gets a literal derived from the sanitized value via
//    reassignment.
func sanitizedThenLiteral(c *gin.Context) {
	raw := c.Query("raw")
	_ = html.EscapeString(raw)
	exec.Command("/bin/echo", "done")
}

// 5. Parameterized SQL — the tainted value is bound via `?`, not
//    interpolated. We still flag it with the conservative rule if
//    it matched, but the taint engine must not fire because the
//    argument to Query is a literal.
func parameterizedQuery(c *gin.Context, db *sql.DB) {
	id := c.Param("id")
	_ = id
	db.Query("SELECT * FROM users WHERE id = ?", 1)
}

// 6. Static SSRF target.
func staticHttpGet() {
	http.Get("https://api.example.com/health")
}

// 7. fmt.Sprintf with only literal arguments.
func sprintfStatic() {
	cmd := fmt.Sprintf("echo %s", "hello")
	exec.Command(cmd)
}

// 8. handler(w, r) but neither r nor any derived value reaches
//    a sink — just a static literal.
func unusedHandler(w http.ResponseWriter, r *http.Request) {
	_ = r
	exec.Command("/bin/true")
}
